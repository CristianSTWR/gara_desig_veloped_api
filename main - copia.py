# main.py (PostgreSQL + SQLAlchemy AsyncSession) — REPARADO

from datetime import datetime, timedelta, timezone
import os
import secrets
import hashlib
import uuid
import json
import string
import jwt
import smtplib
from email.message import EmailMessage
import smtplib
from dotenv import load_dotenv
from dateutil.relativedelta import relativedelta
from sqlalchemy.dialects.postgresql import insert
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Form, Query, WebSocket, UploadFile, File, Cookie, Header
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from sqlalchemy import select, and_, func, case, asc, update
from sqlalchemy.exc import DBAPIError
import base64
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse, parse_qs
import httpx
import re
from models import Planes, PaypalEnv, License, PaypalWebhookEvent

from db import get_db

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALG = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_MINUTES = int(os.getenv("ACCESS_MINUTES", "15"))
REFRESH_DAYS = int(os.getenv("REFRESH_DAYS", "60"))
VERIFY_PAYPAL_WEBHOOKS = os.getenv("VERIFY_PAYPAL_WEBHOOKS", "true").lower() == "true"

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
    Retorna license_id (UUID como str).
    """
    # 1) Buscar licencia
    res = await db.execute(
        text("""
            SELECT id, status, max_devices, expires_at
            FROM licenses
            WHERE license_key = :k
            LIMIT 1
        """),
        {"k": licenseKey},
    )
    lic = res.mappings().first()

    if not lic:
        raise HTTPException(status_code=401, detail="Licencia inválida")
    if lic["status"] != "active": raise HTTPException(status_code=403, detail="Licencia desactivada")

    if lic["expires_at"] is not None:
        # OJO: esto usa utcnow() naive. Si tu DB guarda timestamptz, lo ideal es comparar en UTC consistente.
        if datetime.utcnow() >= lic["expires_at"]:
            raise HTTPException(status_code=403, detail="Licencia expirada")

    license_id = lic["id"]
    max_devices = int(lic["max_devices"] or 1)

    # 2) Ver si el device existe
    res = await db.execute(
        text("""
            SELECT id, revoked
            FROM license_devices
            WHERE license_id = :lid AND device_id = :did
            LIMIT 1
        """),
        {"lid": license_id, "did": deviceId},
    )
    dev = res.mappings().first()

    if dev:
        if bool(dev["revoked"]) is True:
            raise HTTPException(status_code=403, detail="Dispositivo revocado")

        await db.execute(
            text("""
                UPDATE license_devices
                SET last_seen_at = NOW()
                WHERE license_id = :lid AND device_id = :did
            """),
            {"lid": license_id, "did": deviceId},
        )
        await db.commit()
        return str(license_id)

    # 3) Contar devices activos
    res = await db.execute(
        text("""
            SELECT COUNT(*) AS c
            FROM license_devices
            WHERE license_id = :lid AND revoked = FALSE
        """),
        {"lid": license_id},
    )
    count_active = int(res.mappings().first()["c"])

    if count_active >= max_devices:
        raise HTTPException(status_code=409, detail="Límite de dispositivos alcanzado")

    # 4) Insertar device nuevo (UUID generado en Python)
    device_row_id = str(uuid.uuid4())

    await db.execute(
        text("""
            INSERT INTO license_devices
              (id, license_id, device_id, first_activated_at, last_seen_at, revoked)
            VALUES
              (:id, :lid, :did, NOW(), NOW(), FALSE)
        """),
        {"id": device_row_id, "lid": license_id, "did": deviceId},
    )
    await db.commit()
    return str(license_id)

async def create_refresh_session(db: AsyncSession, license_id: str, deviceId: str) -> str:
    """
    Crea una sesión de refresh en license_sessions.
    FIX CLAVE: interval con multiplicación, no concatenación de strings.
    """
    refresh = issue_refresh_token()
    r_hash = sha256_hex(refresh)
    sess_id = str(uuid.uuid4())

    await db.execute(
        text("""
            INSERT INTO license_sessions
              (id, license_id, device_id, refresh_token_hash, issued_at, expires_at, revoked)
            VALUES
              (:id, :lid, :did, :h, NOW(), NOW() + (:days * INTERVAL '1 day'), FALSE)
        """),
        {"id": sess_id, "lid": license_id, "did": deviceId, "h": r_hash, "days": REFRESH_DAYS},
    )
    await db.commit()
    return refresh

async def validate_refresh(db: AsyncSession, refreshToken: str, deviceId: str) -> str:
    r_hash = sha256_hex(refreshToken)

    res = await db.execute(
        text("""
            SELECT l.license_key, ls.device_id, ls.expires_at, ls.revoked
            FROM license_sessions ls
            JOIN licenses l ON l.id = ls.license_id
            WHERE ls.refresh_token_hash = :h
            LIMIT 1
        """),
        {"h": r_hash},
    )
    rec = res.mappings().first()

    if not rec:
        raise HTTPException(status_code=401, detail="Refresh token inválido")
    if bool(rec["revoked"]) is True:
        raise HTTPException(status_code=401, detail="Refresh token revocado")
    if rec["expires_at"] is None or datetime.utcnow() >= rec["expires_at"]:
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
    license_id = await ensure_license_ok(db, req.licenseKey, req.deviceId)
    access = issue_access_token(req.licenseKey, req.deviceId)
    refresh = await create_refresh_session(db, license_id, req.deviceId)
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
    correo_user: str
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
    
    print('CORREO DEL USUARIO', body.correo_user)

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

    env_value = body.env.value if hasattr(body.env, "value") else str(body.env)

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
            subscriber_email=body.correo_user,
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
def paypal_return():
    return {"ok": True, "status": "ACTIVE"}

from sqlalchemy import select, desc
from fastapi import Depends, HTTPException

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
    sub = q.scalar_one_or_none()
    if not sub:
        return {"ok": False, "msg": "No hay suscripción activa"}

    # ✅ Buscar licencia por subscription_id (guardado en licenses.user_id)
    q2 = await db.execute(
        select(License)
        .where(License.user_id == sub.paypal_subscription_id)
        .order_by(desc(License.created_at))
        .limit(1)
    )
    lic = q2.scalar_one_or_none()

    return {
        "ok": True,
        "subscription_id": sub.paypal_subscription_id,
        "status": sub.status,
        "license_key": lic.license_key if lic else None,
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
    # ✅ DEV BYPASS: permite Invoke-RestMethod sin headers
    if not VERIFY_PAYPAL_WEBHOOKS:
        return True

    # Headers que PayPal SIEMPRE manda para verificar
    transmission_id = request.headers.get("paypal-transmission-id")
    transmission_time = request.headers.get("paypal-transmission-time")
    cert_url = request.headers.get("paypal-cert-url")
    auth_algo = request.headers.get("paypal-auth-algo")
    transmission_sig = request.headers.get("paypal-transmission-sig")

    if not PAYPAL_WEBHOOK_ID:
        raise HTTPException(status_code=500, detail="PAYPAL_WEBHOOK_ID is not set")

    if not all([transmission_id, transmission_time, cert_url, auth_algo, transmission_sig]):
        raise HTTPException(
            status_code=400,
            detail="Missing PayPal verification headers",
        )

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

def _extract_subscription_id(event_type: str | None, body: dict) -> str | None:
    resource = body.get("resource") or {}

    subscription_id = None

    # Eventos de suscripción "nativos" (BILLING.SUBSCRIPTION.*)
    if body.get("resource_type") == "subscription" or (event_type or "").startswith("BILLING.SUBSCRIPTION."):
        subscription_id = resource.get("id")

    # Eventos de pago/sale/capture
    if not subscription_id:
        subscription_id = resource.get("billing_agreement_id")

    return subscription_id


def _extract_resource_id(body: dict) -> str | None:
    resource = body.get("resource") or {}
    return (
        resource.get("id")
        or resource.get("billing_agreement_id")
        or resource.get("custom_id")
        or None
    )


async def _register_paypal_event(db: AsyncSession, *, env: PaypalEnv, body: dict) -> tuple[bool, int | None]:
    """
    Inserta el evento en paypal_webhook_events (idempotente).
    Retorna: (is_duplicate, event_row_id)
    """
    paypal_event_id = body.get("id")  # PayPal EVENT id (normalmente viene como "id")
    event_type = body.get("event_type") or "UNKNOWN"

    if not paypal_event_id:
        raise HTTPException(status_code=400, detail="Webhook PayPal sin body.id (paypal_event_id)")

    resource_id = _extract_resource_id(body)

    stmt = (
        insert(PaypalWebhookEvent)
        .values(
            env=env,
            paypal_event_id=paypal_event_id,
            event_type=event_type,
            resource_id=resource_id,
            payload=body,
            processing_status="received",
        )
        .on_conflict_do_nothing(index_elements=["env", "paypal_event_id"])
        .returning(PaypalWebhookEvent.id)
    )

    res = await db.execute(stmt)
    new_id = res.scalar_one_or_none()
    return (new_id is None), new_id


async def _mark_paypal_event(db: AsyncSession, *, event_row_id: int, status: str):
    await db.execute(
        update(PaypalWebhookEvent)
        .where(PaypalWebhookEvent.id == event_row_id)
        .values(
            processing_status=status,   # processed|failed
            processed_at=datetime.now(timezone.utc),
        )
    )


@app.post("/paypal/webhook")
async def paypal_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()

    # ✅ ENV (ajústalo a tu config real)
    # Si guardas env="sandbox" en PaypalSubscription, usa sandbox aquí.
    env = PaypalEnv.sandbox  # en producción: PaypalEnv.live

    # ✅ 0) REGISTRAR EVENTO (SIEMPRE PRIMERO) + idempotencia
    try:
        is_dup, event_row_id = await _register_paypal_event(db, env=env, body=body)
        await db.commit()  # commit SOLO del log
    except Exception as e:
        await db.rollback()
        # Para no provocar reintentos infinitos de PayPal, responde 200
        return {"ok": True, "msg": f"No se pudo registrar el evento: {str(e)}"}

    # Si es duplicado, no reproceses
    if is_dup:
        return {"ok": True, "duplicate": True}

    try:
        # 1) Verificar firma (solo si está activado)
        if VERIFY_PAYPAL_WEBHOOKS:
            token = await get_access_token()
            await verify_paypal_webhook(request, body, token)
        # else: DEV ONLY

        # 2) Procesar evento
        event_type = body.get("event_type")
        resource = body.get("resource", {}) or {}

        # ✅ subscription_id robusto
        subscription_id = _extract_subscription_id(event_type, body)

        # status
        status = resource.get("status")

        # user_id (custom_id) puede venir o no según evento
        user_id = resource.get("custom_id")

        # 3) DB update
        if not subscription_id:
            # No puedo asociar nada, pero el evento ya quedó logueado
            await _mark_paypal_event(db, event_row_id=event_row_id, status="processed")
            await db.commit()
            return {"ok": True, "msg": "No subscription_id found in webhook"}

        q = await db.execute(
            select(PaypalSubscription)
            .where(PaypalSubscription.paypal_subscription_id == subscription_id)
            .order_by(desc(PaypalSubscription.created_at))
            .limit(1)
        )
        row = q.scalar_one_or_none()

        if not row:
            # crear
            row = PaypalSubscription(
                env="sandbox",
                user_id=user_id or "UNKNOWN",
                paypal_plan_id=resource.get("plan_id"),
                paypal_subscription_id=subscription_id,
                status=status or "UNKNOWN",
                approve_url=None,
                raw=body,
            )
            db.add(row)
            await db.flush()  # asegura row.id si lo necesitas
        else:
            row.status = status or row.status
            row.raw = body

        # ✅ ACTIVAR (cuando se activa la suscripción)
        is_active = (event_type == "BILLING.SUBSCRIPTION.ACTIVATED" or status == "ACTIVE")

        if is_active and getattr(row, "license_id", None) is None:
            key = None
            lic = None

            for _ in range(5):
                key = generate_license_key()

                # ⚠️ Si tu diseño REAL es que License.user_id sea el machine_id:
                # usa: user_id=(row.user_id or user_id or "UNKNOWN")
                # Si tu diseño es usar subscription_id como "user_id" de licencia, deja esto:
                lic = License(
                    user_id=subscription_id,
                    license_key=key,
                    status="active",
                    max_devices=2,
                    notes=f"Created from PayPal webhook {subscription_id}",
                )
                db.add(lic)

                try:
                    await db.flush()
                    row.license_id = lic.id
                    break
                except Exception:
                    await db.rollback()

                    # Re-obtener la suscripción para evitar estado inválido
                    q2 = await db.execute(
                        select(PaypalSubscription)
                        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
                        .order_by(desc(PaypalSubscription.created_at))
                        .limit(1)
                    )
                    row = q2.scalar_one()

            # Enviar correo si hay email guardado y key creada
            if row and getattr(row, "subscriber_email", None) and key:
                enviar_correo(
                    row.subscriber_email,
                    key,
                    max_devices="2",
                    plan="LUNA PREMIUM",
                    renovacion="21/2/2026",
                    subscription_id=subscription_id,
                )
            else:
                print("Esta suscripción no tiene correo guardado aún")

        # ✅ Pagos mensuales: sale/capture completed
        is_payment_ok = event_type in ("PAYMENT.SALE.COMPLETED", "PAYMENT.CAPTURE.COMPLETED")

        if is_payment_ok:
            qlic = await db.execute(
                select(License)
                .where(License.user_id == subscription_id)
                .limit(1)
            )
            lic = qlic.scalar_one_or_none()

            if not lic:
                for _ in range(5):
                    key = generate_license_key()
                    lic = License(
                        user_id=subscription_id,
                        license_key=key,
                        status="active",
                        max_devices=2,
                        notes=f"Activated by payment webhook {subscription_id}",
                    )
                    db.add(lic)
                    try:
                        await db.flush()
                        break
                    except Exception:
                        await db.rollback()
            else:
                if lic.status != "active":
                    lic.status = "active"

        # ✅ REVOCAR
        if event_type in (
            "BILLING.SUBSCRIPTION.CANCELLED",
            "BILLING.SUBSCRIPTION.SUSPENDED",
            "BILLING.SUBSCRIPTION.EXPIRED",
        ):
            if getattr(row, "license_id", None):
                lic = await db.get(License, row.license_id)
                if lic:
                    lic.status = "revoked"

        # ✅ Marcar evento como processed + commit final
        await _mark_paypal_event(db, event_row_id=event_row_id, status="processed")
        await db.commit()
        return {"ok": True}

    except Exception as e:
        await db.rollback()

        # ✅ Marcar evento como failed (commit separado)
        try:
            await _mark_paypal_event(db, event_row_id=event_row_id, status="failed")
            await db.commit()
        except Exception:
            await db.rollback()

        # Responder 200 para que PayPal no reintente infinito.
        return {"ok": True, "msg": "Evento registrado pero falló el procesamiento", "error": str(e)}


# 
class CreateProductBody(BaseModel):
    name: str = "LUNA Premium"
    description: str = "Suscripción mensual a LUNA"
    
@app.post("/paypal/create-product")
async def create_product(body: CreateProductBody):
    token = await get_access_token()

    payload = {
        "name": body.name,
        "type": "SERVICE",
        "category": "SOFTWARE",
        "description": body.description,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/catalogs/products",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    return r.json()

class CreatePlanBody(BaseModel):
    product_id: str
    price: str = "9.99"
    currency: str = "USD"

@app.post("/paypal/create-plan")
async def create_plan(body: CreatePlanBody):
    token = await get_access_token()

    payload = {
        "product_id": body.product_id,
        "name": "LUNA Mensual",
        "status": "ACTIVE",
        "billing_cycles": [
            {
                "frequency": {"interval_unit": "MONTH", "interval_count": 1},
                "tenure_type": "REGULAR",
                "sequence": 1,
                "total_cycles": 0,
                "pricing_scheme": {
                    "fixed_price": {"value": body.price, "currency_code": body.currency}
                },
            }
        ],
        "payment_preferences": {
            "auto_bill_outstanding": True,
            "setup_fee_failure_action": "CANCEL",
            "payment_failure_threshold": 3,
        },
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/plans",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    return r.json()

# Extraer datos licencias desde paypal

@app.get("/license/extract")
async def extract_license_info(
    license_key: str = Query(..., min_length=5),
    db: AsyncSession = Depends(get_db),
):
    # 1) Buscar licencia por key
    q = await db.execute(select(License).where(License.license_key == license_key))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    # 2) Tomar subscription_id desde la BD (licenses.user_id)
    subscription_id = (lic.user_id or "").strip()
    if not subscription_id:
        raise HTTPException(
            status_code=400,
            detail="Esta licencia no tiene subscription_id en licenses.user_id",
        )

    # 3) Consultar PayPal
    token = await get_access_token()
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail={"paypal_error": r.json()})

    data = r.json()

    # 4) Extraer info útil
    paypal_status = data.get("status")  # ACTIVE, CANCELLED, SUSPENDED, etc.

    billing_info = data.get("billing_info") or {}
    last_payment = billing_info.get("last_payment") or {}
    last_payment_time = last_payment.get("time")
    last_payment_amount = (last_payment.get("amount") or {}).get("value")
    last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")
    next_billing_time = billing_info.get("next_billing_time")

    # 5) Sincronizar estado local
    if paypal_status != "ACTIVE":
        lic.status = "revoked"
    else:
        lic.status = "active"

    await db.commit()

    return {
        "ok": True,
        "license": {
            "license_key": lic.license_key,
            "status_local": lic.status,
            "subscription_id": subscription_id,
        },
        "paypal": {
            "status": paypal_status,
            "last_payment_time": last_payment_time,
            "last_payment_amount": last_payment_amount,
            "last_payment_currency": last_payment_currency,
            "next_billing_time": next_billing_time,
        },
    }
    
VERIFY_TTL_HOURS = 12          # cada cuánto refrescar contra PayPal
PAYPAL_FAIL_GRACE_HOURS = 48   # si PayPal falla, cuánto tiempo confiar en cache local

def parse_iso(dt: str | None):
    if not dt:
        return None
    return datetime.fromisoformat(dt.replace("Z", "+00:00"))

def utcnow():
    return datetime.now(timezone.utc)

def is_stale(last_sync_at: datetime | None, ttl_hours: int) -> bool:
    if not last_sync_at:
        return True
    return (utcnow() - last_sync_at) > timedelta(hours=ttl_hours)

def can_trust_cache(last_sync_at: datetime | None, grace_hours: int) -> bool:
    if not last_sync_at:
        return False
    return (utcnow() - last_sync_at) <= timedelta(hours=grace_hours)

def compute_premium_from_local(lic) -> bool:
    # Regla simple: paypal_status ACTIVE y licencia active
    if (lic.paypal_status or "").upper() != "ACTIVE":
        return False
    if (lic.status or "").lower() != "active":
        return False
    return True

async def refresh_from_paypal(subscription_id: str):
    token = await get_access_token()
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail={"paypal_error": r.json()})
    return r.json()

@app.get("/license/verify")
async def verify_license(
    license_key: str = Query(..., min_length=5),
    force_refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    # 1) Buscar licencia
    q = await db.execute(select(License).where(License.license_key == license_key))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    # 2) Resolver subscription_id (nuevo campo primero, fallback al user_id antiguo)
    subscription_id = (getattr(lic, "paypal_subscription_id", None) or getattr(lic, "user_id", None) or "").strip()
    if not subscription_id:
        return {
            "ok": True,
            "premium": False,
            "reason": "NO_SUBSCRIPTION_ID",
            "license": {"license_key": lic.license_key, "status_local": lic.status},
            "paypal": None,
        }

    # 3) Decisión rápida desde BD
    premium_local = compute_premium_from_local(lic)

    # 4) Si está fresco y no pidieron refresh: devuelve directo
    if not force_refresh and not is_stale(getattr(lic, "last_sync_at", None), VERIFY_TTL_HOURS):
        return {
            "ok": True,
            "premium": premium_local,
            "source": "CACHE",
            "license": {
                "license_key": lic.license_key,
                "status_local": lic.status,
                "subscription_id": subscription_id,
                "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
            },
            "paypal": {
                "status": lic.paypal_status,
                "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                "last_payment_currency": lic.last_payment_currency,
                "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
            },
        }

    # 5) Refrescar con PayPal (si se puede)
    try:
        data = await refresh_from_paypal(subscription_id)

        paypal_status = (data.get("status") or "").upper()

        billing_info = data.get("billing_info") or {}
        last_payment = billing_info.get("last_payment") or {}

        # Guardar en BD
        lic.user_id = subscription_id
        lic.paypal_status = paypal_status
        lic.last_payment_time = parse_iso(last_payment.get("time"))
        lic.last_payment_amount = (last_payment.get("amount") or {}).get("value")
        lic.last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")
        lic.next_billing_time = parse_iso(billing_info.get("next_billing_time"))
        lic.last_sync_at = utcnow()

        # Sincronizar estado local básico
        lic.status = "active" if paypal_status == "ACTIVE" else "revoked"

        await db.commit()
        await db.refresh(lic)

        premium_final = compute_premium_from_local(lic)

        return {
            "ok": True,
            "premium": premium_final,
            "source": "PAYPAL_REFRESH",
            "license": {
                "license_key": lic.license_key,
                "status_local": lic.status,
                "subscription_id": subscription_id,
                "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
            },
            "paypal": {
                "status": lic.paypal_status,
                "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                "last_payment_currency": lic.last_payment_currency,
                "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
            },
        }

    except Exception as e:
        # 6) Si PayPal falla: usar cache si es confiable (grace window)
        if can_trust_cache(getattr(lic, "last_sync_at", None), PAYPAL_FAIL_GRACE_HOURS):
            return {
                "ok": True,
                "premium": premium_local,
                "source": "CACHE_FALLBACK",
                "warning": "PAYPAL_UNAVAILABLE_USING_CACHE",
                "license": {
                    "license_key": lic.license_key,
                    "status_local": lic.status,
                    "subscription_id": subscription_id,
                    "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
                },
                "paypal": {
                    "status": lic.paypal_status,
                    "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                    "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                    "last_payment_currency": lic.last_payment_currency,
                    "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
                },
            }

        # Si no hay cache confiable: bloquear (seguridad)
        raise HTTPException(
            status_code=503,
            detail={
                "msg": "PayPal no disponible y no hay cache confiable. Intenta de nuevo.",
                "error": str(e),
            },
        )
        

def enviar_correo(destinatario: str, key, max_devices: str, plan: str, renovacion: str, subscription_id: str):
    HTML_CONTENT = f"""
    <!DOCTYPE html>
        <html lang="es">
        <head>
        <meta charset="UTF-8">
        <title>Licencia LUNA</title>
        </head>
        <body style="margin:0;padding:0;background:#c7cfe9;font-family:Arial,Helvetica,sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#c7cfe9;padding:20px 0;">
        <tr>
        <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#111a2e;border-radius:14px;border:1px solid #223053;">

        <!-- Header -->
        <tr>
        <td style="padding:24px;color:#ffffff;">
        <h1 style="margin:0;font-size:22px;letter-spacing:2px;">L U N A</h1>
        <p style="margin:4px 0 0;color:#a9b0c3;font-size:12px;">Licencia & Suscripción</p>
        </td>
        </tr>

        <!-- Contenido principal -->
        <tr>
        <td style="padding:0 24px 24px;color:#ffffff;">
        <h2 style="font-size:20px;margin:0 0 8px;">¡Gracias por tu compra! 🎉</h2>
        <p style="color:#c7cce0;font-size:14px;line-height:1.6;">
        Tu licencia de <strong>LUNA</strong> ya está activa. Guarda este correo, contiene la información
        necesaria para usar tu app.
        </p>

        <!-- Licencia -->
        <div style="margin:20px 0;">
        <p style="margin:0 0 6px;color:#a9b0c3;font-size:12px;">Tu clave de licencia:</p>
        <div style="background:#0b1224;border:1px dashed #2a3a66;border-radius:10px;
        padding:12px;font-family:Consolas,monospace;font-size:16px;">
        {key}
        </div>
        <p style="margin:6px 0 0;color:#a9b0c3;font-size:12px;">
        Máximo de dispositivos: <strong style="color:#fff;">{max_devices}</strong>
        </p>
        </div>

        <!-- Detalles -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#0b1224;
        border:1px solid #223053;border-radius:10px;padding:12px;margin-top:10px;">
        <tr>
        <td style="color:#a9b0c3;font-size:12px;">Plan</td>
        <td align="right" style="color:#ffffff;font-size:12px;"><strong>{plan}</strong></td>
        </tr>
        <tr>
        <td style="color:#a9b0c3;font-size:12px;">Estado</td>
        <td align="right" style="color:#ffffff;font-size:12px;"><strong>ACTIVA</strong></td>
        </tr>
        <tr>
        <td style="color:#a9b0c3;font-size:12px;">Próxima renovación</td>
        <td align="right" style="color:#ffffff;font-size:12px;"><strong>{renovacion}</strong></td>
        </tr>
        <tr>
        <td style="color:#a9b0c3;font-size:12px;">ID Suscripción</td>
        <td align="right" style="color:#ffffff;font-size:12px;font-family:Consolas,monospace;">
        {subscription_id}
        </td>
        </tr>
        </table>

        <!-- Cómo activar -->
        <div style="margin-top:18px;color:#c7cce0;font-size:14px;line-height:1.6;">
        <strong style="color:#fff;">Cómo activar tu licencia:</strong>
        <ol style="margin:8px 0 0 18px;padding:0;">
        <li>Abre la aplicación LUNA.</li>
        <li>Pega tu clave.</li>
        <li>Dale al botón de activar ahora.</li>
        </ol>
        </div>

        <!-- Botón -->
        <div style="margin-top:18px;">
        <a href="{{APP_OPEN_URL}}" style="background:#6d5efc;color:#fff;
        padding:12px 18px;border-radius:10px;font-size:14px;font-weight:bold;
        text-decoration:none;display:inline-block;">
        Abrir LUNA
        </a>
        </div>

        <!-- Soporte -->
        <p style="margin-top:16px;color:#a9b0c3;font-size:12px;line-height:1.6;">
        Si tienes algún problema, responde a este correo indicando tu <strong>License Key</strong>
        y tu <strong>ID de suscripción</strong>.
        No compartas tu clave públicamente.
        </p>

        <hr style="border:none;border-top:1px solid #223053;margin:18px 0;">

        <p style="color:#8f96ad;font-size:11px;">
        © 2026 LUNA. Todos los derechos reservados.
        </p>
        </td>
        </tr>

        </table>
        </td>
        </tr>
        </table>
        </body>
        </html>
    """

    msg = EmailMessage()
    msg.set_content(f"Su código de verificación es:")  # Texto plano
    msg.add_alternative(HTML_CONTENT, subtype="html")

    msg["Subject"] = "Código de verificación | Reservas Express"
    msg["From"] = "Reservas Express <contactjuegosilimitados@gmail.com>"
    msg["To"] = destinatario

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login("contactjuegosilimitados@gmail.com", "eghh betm mobn evnf")
            smtp.send_message(msg)
        print("Correo enviado con éxito a", destinatario)
        return True
    except Exception as e:
        print("Error al enviar correo:", e)
        return False
    

@app.get("/paypal/verify-subscription")
async def verify_subscription(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    # 1) Buscar última suscripción del usuario
    q = await db.execute(
        select(PaypalSubscription)
        .where(PaypalSubscription.user_id == user_id)
        .order_by(PaypalSubscription.created_at.desc())
        .limit(1)
    )
    sub = q.scalar_one_or_none()

    if not sub:
        return { "ok": False, "status": "NO_SUBSCRIPTION" }

    # 2) Consultar PayPal
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{sub.paypal_subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    if r.status_code != 200:
        return { "ok": False, "status": "PAYPAL_ERROR" }

    data = r.json()
    paypal_status = data["status"]  # ACTIVE, CANCELLED, SUSPENDED...

    # 3) Buscar licencia usando subscription_id
    q = await db.execute(
        select(License)
        .where(License.user_id == sub.paypal_subscription_id)
        .limit(1)
    )
    license = q.scalar_one_or_none()

    if not license:
        return {
            "ok": False,
            "status": paypal_status,
            "msg": "LICENSE_NOT_FOUND"
        }

    return {
        "ok": paypal_status == "ACTIVE",
        "subscription_id": sub.paypal_subscription_id,
        "status": paypal_status,
        "license_key": license.license_key,
    }

    
