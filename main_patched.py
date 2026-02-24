# main.py (PostgreSQL + SQLAlchemy AsyncSession) — REPARADO

from datetime import datetime, timedelta, timezone
import os
import secrets
import hashlib
import uuid
import json
import string
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Form, Query, WebSocket, UploadFile, File, Cookie, Header
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from sqlalchemy import select, and_, func, case, asc
from sqlalchemy.exc import DBAPIError
import base64
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse, parse_qs
import httpx
import re
from models import Planes, PaypalEnv, License

from db import get_db

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALG = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_MINUTES = int(os.getenv("ACCESS_MINUTES", "15"))
REFRESH_DAYS = int(os.getenv("REFRESH_DAYS", "60"))

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET no está definido en el entorno")

app = FastAPI(title="LUNA Licensing API")

PAYPAL_BASE_URL = os.getenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
PAYPAL_RETURN_URL = os.getenv("PAYPAL_RETURN_URL", "https://francisca-tineal-estela.ngrok-free.dev/paypal/return")
PAYPAL_CANCEL_URL = os.getenv("PAYPAL_CANCEL_URL", "https://francisca-tineal-estela.ngrok-free.dev/paypal/cancel")
APP_CANCEL = "luna://paypal/cancel"

# =========================
# MODELOS
# =========================
class ActivateRequest(BaseModel):
    licenseKey: str = Field(..., min_length=5)
    deviceId: str = Field(..., min_length=16)

class ActivateResponse(BaseModel):
    accessToken: str
    refreshToken: str

class RefreshRequest(BaseModel):
    refreshToken: str = Field(..., min_length=10)
    deviceId: str = Field(..., min_length=16)

class RefreshResponse(BaseModel):
    accessToken: str
    refreshToken: str

class ValidateRequest(BaseModel):
    deviceId: str = Field(..., min_length=16)

@app.get("/health")
def health():
    return {"ok": True}

# =========================
# HELPERS
# =========================
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def issue_access_token(licenseKey: str, deviceId: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "licenseKey": licenseKey,
        "deviceId": deviceId,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_MINUTES)).timestamp()),
        "typ": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def issue_refresh_token() -> str:
    return secrets.token_urlsafe(48)

async def ensure_license_ok(db: AsyncSession, licenseKey: str, deviceId: str) -> str:
    """
    Valida licencia en Postgres, aplica límite de dispositivos y registra/actualiza el device.
    Retorna license_key (string).
    """
    # 1) Buscar licencia
    res = await db.execute(
        text("""
            SELECT license_key, status, max_devices, expires_at
            FROM licenses
            WHERE license_key = :k
            LIMIT 1
        """),
        {"k": licenseKey},
    )
    lic = res.mappings().first()

    if not lic:
        raise HTTPException(status_code=401, detail="Licencia inválida")
    if lic["status"] != "active":
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    if lic["expires_at"] is not None:
        if datetime.now(timezone.utc) >= lic["expires_at"]:
            raise HTTPException(status_code=403, detail="Licencia expirada")

    max_devices = int(lic["max_devices"] or 1)

    # 2) Ver si el device existe
    res = await db.execute(
        text("""
            SELECT id, revoked
            FROM license_devices
            WHERE license_key = :k AND device_id = :did
            LIMIT 1
        """),
        {"k": licenseKey, "did": deviceId},
    )
    dev = res.mappings().first()

    if dev:
        if bool(dev["revoked"]) is True:
            raise HTTPException(status_code=403, detail="Dispositivo revocado")

        await db.execute(
            text("""
                UPDATE license_devices
                SET last_seen_at = NOW()
                WHERE license_key = :k AND device_id = :did
            """),
            {"k": licenseKey, "did": deviceId},
        )
        await db.commit()
        return licenseKey

    # 3) Contar devices activos
    res = await db.execute(
        text("""
            SELECT COUNT(*) AS c
            FROM license_devices
            WHERE license_key = :k AND revoked = FALSE
        """),
        {"k": licenseKey},
    )
    count_active = int(res.mappings().first()["c"])

    if count_active >= max_devices:
        raise HTTPException(status_code=409, detail="Límite de dispositivos alcanzado")

    # 4) Insertar device nuevo
    await db.execute(
        text("""
            INSERT INTO license_devices
              (license_key, device_id, first_activated_at, last_seen_at, revoked)
            VALUES
              (:k, :did, NOW(), NOW(), FALSE)
        """),
        {"k": licenseKey, "did": deviceId},
    )
    await db.commit()
    return licenseKey

async def create_refresh_session(db: AsyncSession, license_key: str, deviceId: str) -> str:
    """
    Crea/actualiza un refresh token en refresh_tokens.
    """
    refresh = issue_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_DAYS)

    await db.execute(
        text("""
            INSERT INTO refresh_tokens
              (token, license_key, device_id, revoked, created_at, expires_at)
            VALUES
              (:t, :k, :did, FALSE, NOW(), :exp)
            ON CONFLICT (license_key, device_id)
            DO UPDATE SET
              token = EXCLUDED.token,
              revoked = FALSE,
              created_at = NOW(),
              expires_at = EXCLUDED.expires_at
        """),
        {"t": refresh, "k": license_key, "did": deviceId, "exp": expires_at},
    )
    await db.commit()
    return refresh

async def validate_refresh(db: AsyncSession, refreshToken: str, deviceId: str) -> str:
    res = await db.execute(
        text("""
            SELECT license_key, device_id, expires_at, revoked
            FROM refresh_tokens
            WHERE token = :t
            LIMIT 1
        """),
        {"t": refreshToken},
    )
    rec = res.mappings().first()

    if not rec:
        raise HTTPException(status_code=401, detail="Refresh token inválido")
    if bool(rec["revoked"]) is True:
        raise HTTPException(status_code=401, detail="Refresh token revocado")
    if rec["expires_at"] is None or datetime.now(timezone.utc) >= rec["expires_at"]:
        raise HTTPException(status_code=401, detail="Refresh token expirado")
    if rec["device_id"] != deviceId:
        raise HTTPException(status_code=401, detail="Refresh token no pertenece a este dispositivo")

    return rec["license_key"]

# =========================
# ENDPOINTS
# =========================
@app.post("/activate", response_model=ActivateResponse)
async def activate(req: ActivateRequest, db: AsyncSession = Depends(get_db)):
    print('asjdasjd')
    license_key = await ensure_license_ok(db, req.licenseKey, req.deviceId)
    access = issue_access_token(license_key, req.deviceId)
    refresh = await create_refresh_session(db, license_key, req.deviceId)
    print('jasdasjdj')
    return {"accessToken": access, "refreshToken": refresh}

@app.post("/refresh", response_model=RefreshResponse)
async def refresh(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        license_key = await validate_refresh(db, req.refreshToken, req.deviceId)
        await ensure_license_ok(db, license_key, req.deviceId)
        new_access = issue_access_token(license_key, req.deviceId)
        return {"accessToken": new_access, "refreshToken": req.refreshToken}
    except DBAPIError:
        # si quieres ver el error real en consola, puedes loguearlo antes de responder
        raise HTTPException(status_code=503, detail="DB no disponible, intenta de nuevo")

@app.post("/validate")
async def validate(
    req: ValidateRequest,
    authorization: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta Bearer token")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Access token inválido")

    if payload.get("deviceId") != req.deviceId:
        raise HTTPException(status_code=401, detail="Token no pertenece a este dispositivo")

    lic_key = payload.get("licenseKey")
    if not lic_key:
        raise HTTPException(status_code=401, detail="Token inválido")

    await ensure_license_ok(db, lic_key, req.deviceId)

    return {"ok": True}

# Get planes
@app.get("/plans/{plan_key}")
async def get_plan(
    plan_key: str,
    env: PaypalEnv = Query(PaypalEnv.sandbox, description="sandbox o live"),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(Planes)
        .where(
            Planes.plan_key == plan_key,
            Planes.env == env,
            Planes.is_active == True,
        )
        .limit(1)
    )

    result = await db.execute(stmt)
    plan = result.scalars().first()

    if not plan:
        raise HTTPException(status_code=404, detail="Plan no encontrado o inactivo")

    return {
        "plan_key": plan.plan_key,
        "env": plan.env.value if hasattr(plan.env, "value") else str(plan.env),
        "paypal_plan_id": plan.paypal_plan_id,
        "price": str(plan.price),      # Numeric -> string
        "currency": plan.currency,
        "name": plan.name,
        "id": plan.id,
    }
    
    # 
    
# --------- PAYPAL TOKEN ----------
async def get_access_token() -> str:
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Faltan credenciales PayPal")

    auth = base64.b64encode(
        f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()
    ).decode()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/oauth2/token",
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data="grant_type=client_credentials",
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.text)

    return r.json()["access_token"]

class CreateSubscriptionBody(BaseModel):
    plan_id: str
    user_id: str
    env: PaypalEnv = PaypalEnv.sandbox
    
from sqlalchemy import select, desc
from models import PaypalSubscription

@app.post("/paypal/create-subscription")
async def create_subscription(
    body: CreateSubscriptionBody,
    db: AsyncSession = Depends(get_db),
):
    token = await get_access_token()

    payload = {
        "plan_id": body.plan_id,
        "custom_id": body.user_id,
        "application_context": {
            "brand_name": "LUNA",
            "user_action": "SUBSCRIBE_NOW",
            "return_url": PAYPAL_RETURN_URL,
            "cancel_url": PAYPAL_CANCEL_URL,
        },
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )
        
        

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    data = r.json()
    approve_url = next((l["href"] for l in data.get("links", []) if l.get("rel") == "approve"), None)

    paypal_subscription_id = data.get("id")
    paypal_status = data.get("status") or "CREATED"

    env_value = body.env  # Enum PaypalEnv

    # ✅ Busca el registro mas reciente para (user_id, env, plan_id)
    q = await db.execute(
        select(PaypalSubscription)
        .where(
            PaypalSubscription.user_id == body.user_id,
            PaypalSubscription.env == env_value,
            PaypalSubscription.paypal_plan_id == body.plan_id,
        )
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    row = q.scalar_one_or_none()

    if row:
        # ✅ Actualiza el existente
        row.paypal_subscription_id = paypal_subscription_id
        row.status = paypal_status
        row.approve_url = approve_url
        row.raw = data
    else:
        # ✅ Inserta uno nuevo
        row = PaypalSubscription(
            env=env_value,
            user_id=body.user_id,
            paypal_plan_id=body.plan_id,
            paypal_subscription_id=paypal_subscription_id,
            status=paypal_status,
            approve_url=approve_url,
            raw=data,
        )
        db.add(row)

    await db.commit()

    return {
        "subscription_id": paypal_subscription_id,
        "status": paypal_status,
        "approve_url": approve_url,
    }

@app.get("/paypal/subscription-status")
async def paypal_subscription_status(subscription_id: str):
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    data = r.json()
    return {
        "id": data.get("id"),
        "status": data.get("status"),  # ACTIVE / APPROVAL_PENDING / CANCELLED...
    }

def generate_license_key(prefix: str = "LUNA") -> str:
    chars = string.ascii_uppercase + string.digits  # A-Z 0-9
    
    def block(n=4):
        return "".join(secrets.choice(chars) for _ in range(n))
    
    return f"{prefix}-{block()}-{block()}-{block()}"
""" @app.get("/paypal/return")
async def paypal_return(subscription_id: str, db: AsyncSession = Depends(get_db)):
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"}
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    data = r.json()
    status = data.get("status")  # ACTIVE, APPROVAL_PENDING, CANCELLED, etc.
    user_id = data.get("custom_id")  # el que mandaste en create-subscription como custom_id

    # 1) Buscar suscripción
    q = await db.execute(
        select(PaypalSubscription)
        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    row = q.scalar_one_or_none()

    # 2) Crear o actualizar
    if not row:
        row = PaypalSubscription(
            env=data.get("environment") or "sandbox",
            user_id=user_id,
            paypal_plan_id=data.get("plan_id"),
            paypal_subscription_id=subscription_id,
            status=status,
            approve_url=None,
            raw=data,
            # license_id=None  # si existe el campo
        )
        db.add(row)
    else:
        row.status = status
        row.raw = data

    # 3) ✅ Si ya está ACTIVE, crear licencia (una sola vez)
    created_license = None
    if status == "ACTIVE":
        # Idempotencia: si ya tiene licencia asociada, no crear otra
        if getattr(row, "license_id", None) is None:
            # generar key y asegurar unicidad
            # (por si colisiona con UNIQUE, reintenta)
            for _ in range(5):
                key = generate_license_key()
                lic = License(
                    user_id=row.user_id,
                    license_key=key,
                    status="active",
                    max_devices=1,
                    notes=f"Created from PayPal subscription {subscription_id}",
                )
                db.add(lic)
                try:
                    await db.flush()  # obtiene lic.id y valida UNIQUE(license_key) sin commit aún
                    created_license = lic
                    break
                except Exception:
                    # posible colisión unique (muy raro) u otro error => reintenta
                    await db.rollback()
                    # reatacha row porque rollback la saca del estado pending en algunos casos
                    # (alternativa: manejar IntegrityError específicamente)
                    q2 = await db.execute(
                        select(PaypalSubscription)
                        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
                        .order_by(desc(PaypalSubscription.created_at))
                        .limit(1)
                    )
                    row = q2.scalar_one()

            if created_license:
                row.license_id = created_license.id  # requiere columna license_id

    await db.commit()

    return {
        "ok": True,
        "subscription_id": subscription_id,
        "status": status,
        "license": {
            "id": str(created_license.id),
            "license_key": created_license.license_key,
        } if created_license else None
    }
     """
     
@app.get("/paypal/return")
def paypal_cancel():
    return {"ok": True, "status": "ACTIVE"}


class RestoreByLicenseBody(BaseModel):
    license_key: str = Field(..., min_length=5, max_length=64)

@app.post("/paypal/restore-by-license")
async def paypal_restore_by_license(body: RestoreByLicenseBody, db: AsyncSession = Depends(get_db)):
    # 1) Buscar licencia
    res = await db.execute(
        text("""
            SELECT license_key, status, paypal_subscription_id
            FROM licenses
            WHERE license_key = :k
            LIMIT 1
        """),
        {"k": body.license_key},
    )
    lic = res.mappings().first()
    if not lic:
        return {"ok": False, "msg": "Licencia no encontrada"}

    if lic["status"] != "active":
        return {"ok": False, "msg": f"Licencia no activa ({lic['status']})"}

    # 2) Buscar suscripción ligada a esa licencia
    res = await db.execute(
        text("""
            SELECT paypal_subscription_id, status
            FROM paypal_subscriptions
            WHERE license_key = :k
            ORDER BY created_at DESC
            LIMIT 1
        """),
        {"k": body.license_key},
    )
    sub = res.mappings().first()

    if not sub and lic.get("paypal_subscription_id"):
        res = await db.execute(
            text("""
                SELECT paypal_subscription_id, status
                FROM paypal_subscriptions
                WHERE paypal_subscription_id = :sid
                LIMIT 1
            """),
            {"sid": lic["paypal_subscription_id"]},
        )
        sub = res.mappings().first()

    if not sub:
        return {"ok": False, "msg": "No hay suscripción ligada a esta licencia"}

    return {
        "ok": True,
        "license_key": lic["license_key"],
        "subscription_id": sub["paypal_subscription_id"],
        "subscription_status": sub["status"],
    }

@app.get("/paypal/restore")
async def restore(user_id: str, db: AsyncSession = Depends(get_db)):
    q = await db.execute(
        select(PaypalSubscription)
        .where(
            PaypalSubscription.user_id == user_id,
            PaypalSubscription.status == "ACTIVE"
        )
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    row = q.scalar_one_or_none()

    if not row:
        return {"ok": False, "msg": "No hay suscripción activa"}

    return {
        "ok": True,
        "subscription_id": row.paypal_subscription_id,
        "status": row.status,
    }


""" @app.get("/paypal/return")
def paypal_return(subscription_id: str | None = None):
    return RedirectResponse(
        url=f"luna://paypal/success?sub={subscription_id or ''}"
    ) """

@app.get("/paypal/cancel")
def paypal_cancel():
    return {"ok": True, "status": "CANCELLED"}

PAYPAL_WEBHOOK_ID = "34U442868F077541L"

async def verify_paypal_webhook(request: Request, body: dict, token: str):
    # Headers que PayPal SIEMPRE manda para verificar
    transmission_id = request.headers.get("paypal-transmission-id")
    transmission_time = request.headers.get("paypal-transmission-time")
    cert_url = request.headers.get("paypal-cert-url")
    auth_algo = request.headers.get("paypal-auth-algo")
    transmission_sig = request.headers.get("paypal-transmission-sig")

    if not all([transmission_id, transmission_time, cert_url, auth_algo, transmission_sig, PAYPAL_WEBHOOK_ID]):
        raise HTTPException(status_code=400, detail="Missing PayPal verification headers or PAYPAL_WEBHOOK_ID")

    payload = {
        "auth_algo": auth_algo,
        "cert_url": cert_url,
        "transmission_id": transmission_id,
        "transmission_sig": transmission_sig,
        "transmission_time": transmission_time,
        "webhook_id": PAYPAL_WEBHOOK_ID,
        "webhook_event": body,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail={"verify_error": r.json()})

    verification_status = r.json().get("verification_status")
    if verification_status != "SUCCESS":
        raise HTTPException(status_code=400, detail={"verification_status": verification_status})

    return True


@app.post("/paypal/webhook")
async def paypal_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    token = await get_access_token()

    # 1) Verificar firma
    await verify_paypal_webhook(request, body, token)

    # 2) Procesar evento
    event_type = body.get("event_type")
    resource = body.get("resource", {}) or {}

    # En subscripciones, el ID suele venir en resource["id"]
    subscription_id = resource.get("id")

    # status puede venir como resource["status"]
    status = resource.get("status")

    # custom_id normalmente viene dentro del resource (cuando creas subs con custom_id)
    user_id = resource.get("custom_id")

    # 3) Actualizar tu DB según el evento
    if subscription_id:
        q = await db.execute(
            select(PaypalSubscription)
            .where(PaypalSubscription.paypal_subscription_id == subscription_id)
            .order_by(desc(PaypalSubscription.created_at))
            .limit(1)
        )
        row = q.scalar_one_or_none()

        if not row:
            # Si no existe, la creas (seguro)
            row = PaypalSubscription(
                env="sandbox",
                user_id=user_id,
                paypal_plan_id=resource.get("plan_id"),
                paypal_subscription_id=subscription_id,
                status=status or "UNKNOWN",
                approve_url=None,
                raw=body,  # guarda evento completo
            )
            db.add(row)
        else:
            row.status = status or row.status
            row.raw = body

        # Ejemplo de lógica:
        # - Si llega ACTIVATED o status ACTIVE => crear licencia si no existe
        is_active = (event_type == "BILLING.SUBSCRIPTION.ACTIVATED") or (status == "ACTIVE")

        if is_active and getattr(row, "license_id", None) is None:
            # crea licencia una sola vez
            for _ in range(5):
                key = generate_license_key()
                lic = License(
                    user_id=row.user_id,
                    license_key=key,
                    status="active",
                    max_devices=2,
                    paypal_subscription_id=subscription_id,
                    paypal_plan_id=resource.get("plan_id"),
                    notes=f"Created from PayPal webhook {subscription_id}",
                )
                db.add(lic)
                try:
                    await db.flush()
                    row.license_id = lic.id
                    # 🔥 para restaurar por licencia
                    row.license_key = lic.license_key
                    break
                except Exception:
                    await db.rollback()
                    # recargar row tras rollback
                    q2 = await db.execute(
                        select(PaypalSubscription)
                        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
                        .order_by(desc(PaypalSubscription.created_at))
                        .limit(1)
                    )
                    row = q2.scalar_one()

        # - Si llega CANCELLED/SUSPENDED/EXPIRED => revocar/expirar licencia
        if event_type in ("BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.SUSPENDED", "BILLING.SUBSCRIPTION.EXPIRED"):
            if getattr(row, "license_id", None):
                lic = await db.get(License, row.license_id)
                if lic:
                    lic.status = "revoked"  # o "expired"

        await db.commit()

    return {"ok": True}