# main.py (PostgreSQL + SQLAlchemy AsyncSession) — REPARADO

from datetime import datetime, timedelta, timezone
import logging
import os
import secrets
import hashlib
import uuid
import json
import string
import jwt
import smtplib
from email.message import EmailMessage
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
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from config import (
    APP_ENV,
    IS_PROD,
    JWT_SECRET,
    JWT_ALGORITHM,
    ACCESS_MINUTES,
    REFRESH_DAYS,
    PAYPAL_BASE_URL,
    PAYPAL_CLIENT_ID,
    PAYPAL_CLIENT_SECRET,
    PAYPAL_RETURN_URL,
    PAYPAL_CANCEL_URL,
    PAYPAL_WEBHOOK_ID,
    VERIFY_PAYPAL_WEBHOOKS,
    ALLOWED_ORIGINS,
    ALLOWED_HOSTS,
    MAX_BODY_BYTES,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_APP_PASSWORD,
    EMAIL_FROM,
    validate_settings,
)

from security_middleware import SecurityHeadersMiddleware, RequestIdMiddleware, MaxBodySizeMiddleware
from rate_limit import TokenBucketLimiter
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse, parse_qs
import httpx
import re
from models import Planes, PaypalEnv, License, PaypalWebhookEvent, LicenseStatus

from db import get_db

load_dotenv()
validate_settings()

# logging
logging.basicConfig(level=(logging.INFO if IS_PROD else logging.DEBUG))
logger = logging.getLogger("luna")

# FastAPI (docs off in prod)
_docs = None if IS_PROD else "/docs"
_redoc = None if IS_PROD else "/redoc"
app = FastAPI(title="LUNA Licensing API", docs_url=_docs, redoc_url=_redoc)

# Middlewares
app.add_middleware(RequestIdMiddleware)
app.add_middleware(MaxBodySizeMiddleware, max_bytes=MAX_BODY_BYTES)
app.add_middleware(SecurityHeadersMiddleware, is_prod=IS_PROD)

# CORS (set ALLOWED_ORIGINS in env). If empty, do not enable permissive CORS.
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Internal-Key", "X-Request-Id"],
    )

# Allowed hosts (recommended in prod). If empty, allow all.
if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


# Simple in-memory rate limiters (recommended to offload to WAF in production)
#  - sensitive endpoints: 1 req/sec with burst 10 per IP
limiter_sensitive = TokenBucketLimiter(rate_per_sec=1.0, burst=10)
#  - webhook: allow higher, but still avoid abuse
limiter_webhook = TokenBucketLimiter(rate_per_sec=5.0, burst=50)

def _client_ip(request: Request) -> str:
    # If behind proxy, ensure your proxy sets X-Forwarded-For correctly.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _rate_limit(request: Request, limiter: TokenBucketLimiter):
    ip = _client_ip(request)
    ok, retry = limiter.allow(ip)
    if not ok:
        raise HTTPException(status_code=429, detail="Too Many Requests", headers={"Retry-After": str(int(retry) + 1)})

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
# INTERNAL AUTH (optional)
# =========================
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "").strip()

def require_internal_key(x_internal_key: str = Header(default="")):
    """If INTERNAL_API_KEY is set, require X-Internal-Key header."""
    if INTERNAL_API_KEY:
        if not x_internal_key or x_internal_key != INTERNAL_API_KEY:
            raise HTTPException(status_code=403, detail="Forbidden")

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
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

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

    if lic["status"] == "revoked" and lic["status"] != "active":
        raise HTTPException(status_code=405, detail="Licencia revocada")
    if lic["status"] == "expired" and lic["status"] != "active":
        raise HTTPException(status_code=404, detail="Licencia desactivada")


    # 1.1) Verificar expiración (UTC)
    exp_at = lic["expires_at"]
    if exp_at is not None:
        # Si viene naive, asumimos UTC (mejor que comparar naive con aware)
        if getattr(exp_at, "tzinfo", None) is None:
            exp_at = exp_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) >= exp_at:
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
        if bool(dev["revoked"]):
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
    row = res.mappings().first()
    count_active = int(row["c"] or 0)

    if count_active >= max_devices:
        raise HTTPException(status_code=409, detail="Límite de dispositivos alcanzado")

    # 4) Insertar device nuevo
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

    exp_at = rec["expires_at"]  # ✅ SIEMPRE asignado aquí

    if exp_at is None:
        raise HTTPException(status_code=401, detail="Refresh token expirado")

    if exp_at.tzinfo is None:
        exp_at = exp_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) >= exp_at:
        raise HTTPException(status_code=401, detail="Refresh token expirado")

    if rec["device_id"] != deviceId:
        raise HTTPException(status_code=401, detail="Refresh token no pertenece a este dispositivo")

    return rec["license_key"]

# =========================
# ENDPOINTS
# =========================
@app.post("/activate", response_model=ActivateResponse)
async def activate(req: ActivateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _rate_limit(request, limiter_sensitive)
    logger.info("activate request")
    license_id = await ensure_license_ok(db, req.licenseKey, req.deviceId)
    access = issue_access_token(req.licenseKey, req.deviceId)
    refresh = await create_refresh_session(db, license_id, req.deviceId)
    logger.info("activate issued tokens")
    return {"accessToken": access, "refreshToken": refresh}

@app.post("/refresh", response_model=RefreshResponse)
async def refresh(req: RefreshRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _rate_limit(request, limiter_sensitive)
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
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    _rate_limit(request, limiter_sensitive)
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
    
    logger.info("create-subscription for user_id=%s", body.user_id)

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



class ActivateSchema(BaseModel):
    license_key: str

@app.post("/paypal/subscription-activate")
async def paypal_subscription_activate(
    payload: ActivateSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(License).where(License.license_key == payload.license_key)
    result = await db.execute(stmt)
    license = result.scalar_one_or_none()

    if not license:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    if license.paypal_status == "ACTIVE" and not getattr(license, "cancel_requested", False):
        raise HTTPException(
            status_code=409,
            detail={
                "ok": False,
                "msg": "La suscripción ya estaba activa"
            }
        )

    subscription_id = license.user_id
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}/activate",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"reason": "Reactivación de suscripción"}
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    await db.execute(text("SET LOCAL app.verified_write = '1'"))

    license.cancel_requested = False
    license.payment_error = False
    license.last_sync_at = utcnow() if hasattr(license, "last_sync_at") else getattr(license, "last_sync_at", None)

    stmt_sub = (
        select(PaypalSubscription)
        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    result_sub = await db.execute(stmt_sub)
    subscription = result_sub.scalar_one_or_none()

    if subscription:
        subscription.status = "ACTIVE"

    await db.commit()
    await db.refresh(license)

    return {"ok": True}

class SuspendSchema(BaseModel):
    license_key: str
    
@app.post("/paypal/subscription-suspend")
async def paypal_subscription_suspend(
    payload: SuspendSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(License).where(License.license_key == payload.license_key)
    result = await db.execute(stmt)
    license = result.scalar_one_or_none()

    if not license:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    if license.paypal_status == "CANCELLED":
        raise HTTPException(
            status_code=409,
            detail={
                "ok": False,
                "msg": "La suscripción fue cancelada definitivamente y no puede suspenderse"
            }
        )

    if license.paypal_status == "SUSPENDED" and getattr(license, "cancel_requested", False):
        return {"ok": True, "msg": "La suscripción ya estaba suspendida"}

    subscription_id = license.user_id
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}/suspend",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"reason": "Suspensión solicitada por el usuario"}
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    await db.execute(text("SET LOCAL app.verified_write = '1'"))

    license.paypal_status = "SUSPENDED"
    license.cancel_requested = True

    stmt_sub = (
        select(PaypalSubscription)
        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    result_sub = await db.execute(stmt_sub)
    subscription = result_sub.scalar_one_or_none()

    if subscription:
        subscription.status = "SUSPENDED"

    await db.commit()
    await db.refresh(license)

    return {"ok": True}

def _extract_subscription_id_any(event_type: str, body: dict) -> str | None:
        resource = body.get("resource", {}) or {}

        sid = _extract_subscription_id(event_type, body)
        if sid:
            return sid

        for k in (
            "billing_agreement_id",
            "subscription_id",
            "agreement_id",
            "id",
        ):
            v = resource.get(k)
            if isinstance(v, str) and v:
                return v

        supp = resource.get("supplementary_data") or {}
        related = (supp.get("related_ids") or {}) if isinstance(supp, dict) else {}
        for k in (
            "subscription_id",
            "billing_agreement_id",
            "agreement_id",
        ):
            v = related.get(k)
            if isinstance(v, str) and v:
                return v

        links = resource.get("links") or []
        if isinstance(links, list):
            for l in links:
                href = (l or {}).get("href")
                if isinstance(href, str) and "/subscriptions/" in href:
                    return href.split("/subscriptions/")[-1].split("?")[0].strip() or None

        return None
@app.post("/paypal/webhook")
async def paypal_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    _rate_limit(request, limiter_webhook)
    body = await request.json()
    env = PaypalEnv.sandbox

    try:
        is_dup, event_row_id = await _register_paypal_event(db, env=env, body=body)
        await db.commit()
    except Exception as e:
        await db.rollback()
        return {"ok": True, "msg": f"No se pudo registrar el evento: {str(e)}"}

    if is_dup:
        return {"ok": True, "duplicate": True}

    try:
        if VERIFY_PAYPAL_WEBHOOKS:
            token = await get_access_token()
            await verify_paypal_webhook(request, body, token)

        event_type = body.get("event_type")
        resource = body.get("resource", {}) or {}
        subscription_id = _extract_subscription_id_any(event_type, body)
        status = resource.get("status")
        user_id = resource.get("custom_id")

        print("EVENT TYPE:", event_type)
        print("SUBSCRIPTION ID:", subscription_id)
        print("BODY:", body)

        if not subscription_id:
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
            await db.flush()
        else:
            if user_id and row.user_id in (None, "", "UNKNOWN"):
                row.user_id = user_id
            if resource.get("plan_id") and not row.paypal_plan_id:
                row.paypal_plan_id = resource.get("plan_id")
            row.raw = body

        async def get_license():
            qlic = await db.execute(
                select(License)
                .where(License.user_id == subscription_id)
                .order_by(desc(License.created_at))
                .limit(1)
            )
            return qlic.scalar_one_or_none()

        async def create_license_if_missing():
            lic = await get_license()

            if lic:
                return lic, False

            key = generate_license_key()
            lic = License(
                user_id=subscription_id,
                license_key=key,
                status="active",
                max_devices=2,
                notes=f"Activated by PayPal webhook {subscription_id}",
                paypal_status="ACTIVE",
                cancel_requested=False,
            )
            db.add(lic)
            await db.flush()

            if getattr(row, "license_id", None) is None:
                row.license_id = lic.id

            if getattr(row, "subscriber_email", None):
                enviar_correo(
                    row.subscriber_email,
                    key,
                    max_devices="2",
                    plan="LUNA PREMIUM",
                    renovacion="21/2/2026",
                    subscription_id=subscription_id,
                )

            return lic, True

        lic = await get_license()

        if event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
            row.status = "ACTIVE"

            if not lic:
                lic, _ = await create_license_if_missing()

            lic.paypal_status = "ACTIVE"
            lic.cancel_requested = False

            if hasattr(lic, "payment_error"):
                lic.payment_error = False


        elif event_type == "BILLING.SUBSCRIPTION.SUSPENDED":
            row.status = "SUSPENDED"
            if lic:
                lic.paypal_status = "SUSPENDED"
                lic.status = "revoked"

        elif event_type == "BILLING.SUBSCRIPTION.CANCELLED":
            row.status = "CANCELLED"
            if lic:
                lic.paypal_status = "CANCELLED"
                lic.cancel_requested = True
                lic.status = "revoked"

        elif event_type == "BILLING.SUBSCRIPTION.EXPIRED":
            row.status = "EXPIRED"
            if lic:
                lic.paypal_status = "EXPIRED"
                lic.status = "revoked"

        elif event_type == "BILLING.SUBSCRIPTION.PAYMENT.FAILED":
            if lic and hasattr(lic, "payment_error"):
                lic.payment_error = True

        elif event_type in (
            "BILLING.SUBSCRIPTION.PAYMENT.COMPLETED",
            "PAYMENT.SALE.COMPLETED",
            "PAYMENT.CAPTURE.COMPLETED",
        ):
            row.status = "ACTIVE"

            if not lic:
                lic, _ = await create_license_if_missing()

            lic.paypal_status = "ACTIVE"
            lic.cancel_requested = False
            lic.status = "active"

            if hasattr(lic, "payment_error"):
                lic.payment_error = False

            billing_info = body.get("resource", {}).get("billing_info") or {}
            last_payment = billing_info.get("last_payment") or {}

            lp_time = parse_iso(last_payment.get("time"))
            if lp_time and hasattr(lic, "last_payment_time"):
                lic.last_payment_time = lp_time

            if hasattr(lic, "last_payment_amount"):
                lic.last_payment_amount = (last_payment.get("amount") or {}).get("value")

            if hasattr(lic, "last_payment_currency"):
                lic.last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")

            if hasattr(lic, "next_billing_time"):
                lic.next_billing_time = parse_iso(billing_info.get("next_billing_time"))

            if hasattr(lic, "paid_through"):
                lic.paid_through = compute_paid_through_monthly(lp_time)

        else:
            if status:
                row.status = status

        await _mark_paypal_event(db, event_row_id=event_row_id, status="processed")
        await db.commit()
        return {"ok": True, "event_type": event_type, "subscription_id": subscription_id}

    except Exception as e:
        await db.rollback()
        try:
            await _mark_paypal_event(db, event_row_id=event_row_id, status="failed")
            await db.commit()
        except Exception:
            await db.rollback()

        return {
            "ok": True,
            "msg": "Evento registrado pero falló el procesamiento",
            "error": str(e),
        }
# 
class CreateProductBody(BaseModel):
    name: str = "LUNA Premium"
    description: str = "Suscripción mensual a LUNA"
    

@app.post("/paypal/create-product")
async def create_product(
    body: CreateProductBody,
    _=Depends(require_internal_key),
):
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
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
        )

    if r.status_code >= 400:
        try:
            detail = r.json()
        except Exception:
            detail = {"raw": r.text}
        raise HTTPException(status_code=r.status_code, detail=detail)

    return r.json()

class CreatePlanBody(BaseModel):
    product_id: str
    price: str = "9.99"
    currency: str = "USD"

@app.post("/paypal/create-plan")
async def create_plan(
    body: CreatePlanBody,
    _=Depends(require_internal_key),
):
    token = await get_access_token()

    payload = {
        "product_id": body.product_id,
        "name": "LUNA Mensual",
        "billing_cycles": [
            {
                "frequency": {"interval_unit": "MONTH", "interval_count": 1},
                "tenure_type": "REGULAR",
                "sequence": 1,
                "total_cycles": 0,  # 0 = ilimitado
                "pricing_scheme": {
                    "fixed_price": {"value": str(body.price), "currency_code": body.currency}
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
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
        )

    if r.status_code >= 400:
        # Manejo robusto del error
        try:
            detail = r.json()
        except Exception:
            detail = {"raw": r.text}
        raise HTTPException(status_code=r.status_code, detail=detail)

    return r.json()
# Extraer datos licencias desde paypal

@app.get("/license/extract")
async def extract_license_info(
    _=Depends(require_internal_key),

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
 
VERIFY_TTL_HOURS = 6
PAYPAL_FAIL_GRACE_HOURS = 24
CANCEL_REFRESH_GRACE_MINUTES = 5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def safe_upper(v: str | None) -> str:
    return (v or "").strip().upper()

def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def is_dt(v) -> bool:
    return isinstance(v, datetime)

def iso_or_none(v) -> str | None:
    return v.isoformat() if is_dt(v) else None

def get_attr(obj, name: str, default=None):
    return getattr(obj, name, default)

def set_attr_if_exists(obj, name: str, value):
    if hasattr(obj, name):
        setattr(obj, name, value)

def is_stale(last_sync_at: datetime | None, ttl_hours: float) -> bool:
    if not is_dt(last_sync_at):
        return True
    return (utcnow() - last_sync_at).total_seconds() > ttl_hours * 3600

def can_trust_cache(last_sync_at: datetime | None, grace_hours: float) -> bool:
    if not is_dt(last_sync_at):
        return False
    return (utcnow() - last_sync_at).total_seconds() <= grace_hours * 3600

def compute_paid_through_monthly(last_payment_time: datetime | None) -> datetime | None:
    if not is_dt(last_payment_time):
        return None
    return last_payment_time + relativedelta(months=1)

def compute_premium_window(
    paypal_status: str,
    last_payment_time: datetime | None,
    next_billing_time: datetime | None,
) -> tuple[bool, datetime | None]:
    now = utcnow()
    status = safe_upper(paypal_status)

    paid_through = compute_paid_through_monthly(last_payment_time)

    if not paid_through:
        return False, None

    if status in {"EXPIRED", "CANCELLED", "SUSPENDED"}:
        return False, paid_through

    return now < paid_through, paid_through



CANCEL_REFRESH_WINDOW_HOURS = 24
CANCEL_TTL_MINUTES = 15

def refresh_due_to_cancel_requested(lic) -> bool:
    if not bool(get_attr(lic, "cancel_requested", False)):
        return False
    at = get_attr(lic, "cancel_requested_at", None)
    if not at:
        return True  # no sabemos cuándo, refresca siempre
    return utcnow() - at < timedelta(hours=CANCEL_REFRESH_WINDOW_HOURS)

def compute_paid_through_local(lic) -> datetime | None:
    """
    Calcula paid_through aunque no tengas columna:
    - si existe lic.paid_through úsalo
    - si no, usa last_payment_time + 1 mes
    """
    pt = get_attr(lic, "paid_through", None)
    if is_dt(pt):
        return pt

    lpt = get_attr(lic, "last_payment_time", None)
    if is_dt(lpt):
        return compute_paid_through_monthly(lpt)

    return None

def build_response(
    lic,
    subscription_id: str,
    premium: bool,
    source: str,
    paypal_status_real: str | None = None,   # lo que PayPal dijo ahora/último refresh
    paid_through: datetime | None = None,
    warning: str | None = None,
):
    # cached status (lo que tengas guardado)
    paypal_status_cached = get_attr(lic, "paypal_status", None)

    # asegura paid_through aunque sea cache
    paid_through_final = paid_through if is_dt(paid_through) else compute_paid_through_local(lic)

    return {
        "ok": True,
        "premium": premium,
        "source": source,
        **({"warning": warning} if warning else {}),
        "license": {
            "license_key": lic.license_key,
            "status_local": get_attr(lic, "status", None),
            "subscription_id": subscription_id,
            "last_sync_at": iso_or_none(get_attr(lic, "last_sync_at", None)),
            "cancel_requested": bool(get_attr(lic, "cancel_requested", False)),
            "paid_through": iso_or_none(paid_through_final),
        },
        "paypal": {
            # ✅ NO confundir más:
            "status_real": paypal_status_real,     # puede ser None en CACHE
            "status_cached": paypal_status_cached, # lo que está en DB
            # si quieres un solo "status" para el frontend:
            # - en refresh: usa real
            # - en cache: usa cached
            "status": paypal_status_real if paypal_status_real is not None else paypal_status_cached,

            "last_payment_time": iso_or_none(get_attr(lic, "last_payment_time", None)),
            "last_payment_amount": str(get_attr(lic, "last_payment_amount", None))
                if get_attr(lic, "last_payment_amount", None) is not None else None,
            "last_payment_currency": get_attr(lic, "last_payment_currency", None),
            "next_billing_time": iso_or_none(get_attr(lic, "next_billing_time", None)),
        },
    }


def compute_premium_from_local(lic) -> bool:
    paid_through = getattr(lic, "paid_through", None)
    if isinstance(paid_through, datetime):
        return utcnow() < paid_through

    lpt = getattr(lic, "last_payment_time", None)
    if isinstance(lpt, datetime):
        computed = compute_paid_through_monthly(lpt)
        if computed:
            return utcnow() < computed

    return False


async def refresh_from_paypal(subscription_id: str) -> dict:
    """
    Devuelve el JSON de PayPal para una suscripción.
    """
    token = await get_access_token()

    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        r.raise_for_status()
        return r.json()
    
def mark_suspicious(lic, reason: str):
    """
    Marca la licencia como sospechosa y corta el premium.
    """
    if hasattr(lic, "suspicious"):
        lic.suspicious = True

    if hasattr(lic, "suspicious_reason"):
        lic.suspicious_reason = reason[:255]

    if hasattr(lic, "suspicious_at"):
        lic.suspicious_at = utcnow()

    # 🔒 Corte inmediato local
    if hasattr(lic, "status"):
        lic.status = "revoked"
    
@app.get("/license/verify")
async def verify_license(
    _=Depends(require_internal_key),
    license_key: str = Query(..., min_length=5),
    force_refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    q = await db.execute(select(License).where(License.license_key == license_key))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    if bool(get_attr(lic, "suspicious", False)):
        return build_response(
            lic=lic,
            subscription_id=get_attr(lic, "user_id", None),
            premium=False,
            source="SECURITY_BLOCK",
            paypal_status_real=None,
            paid_through=get_attr(lic, "paid_through", None),
            warning="LICENSE_MARKED_SUSPICIOUS",
        )

    subscription_id = (
        (get_attr(lic, "paypal_subscription_id", None) or get_attr(lic, "user_id", None) or "")
        .strip()
    )

    if not subscription_id:
        return {
            "ok": True,
            "premium": False,
            "reason": "NO_SUBSCRIPTION_ID",
            "source": "NO_SUBSCRIPTION_ID",
            "license": {
                "license_key": get_attr(lic, "license_key", None),
                "status_local": get_attr(lic, "status", None),
                "subscription_id": None,
                "last_sync_at": iso_or_none(get_attr(lic, "last_sync_at", None)),
                "cancel_requested": bool(get_attr(lic, "cancel_requested", False)),
                "paid_through": iso_or_none(get_attr(lic, "paid_through", None)),
            },
            "paypal": None,
        }

    last_sync_at = get_attr(lic, "last_sync_at", None)
    cancel_requested = bool(get_attr(lic, "cancel_requested", False))

    cancel_stale = is_stale(last_sync_at, CANCEL_TTL_MINUTES / 60)
    normal_stale = is_stale(last_sync_at, VERIFY_TTL_HOURS)

    must_refresh = bool(force_refresh) or (cancel_requested and cancel_stale) or normal_stale

    if not must_refresh:
        premium_local = compute_premium_from_local(lic)
        return build_response(
            lic=lic,
            subscription_id=subscription_id,
            premium=premium_local,
            source="CACHE",
            paypal_status_real=None,
            paid_through=get_attr(lic, "paid_through", None),
        )

    try:
        data = await refresh_from_paypal(subscription_id)
        paypal_status_real = safe_upper(data.get("status"))

        billing_info = data.get("billing_info") or {}
        last_payment = billing_info.get("last_payment") or {}

        last_payment_time = parse_iso(last_payment.get("time"))
        next_billing_time = parse_iso(billing_info.get("next_billing_time"))

        premium_final, paid_through = compute_premium_window(
            paypal_status=paypal_status_real,
            last_payment_time=last_payment_time,
            next_billing_time=next_billing_time,
        )

        if paid_through and paid_through > utcnow() + timedelta(days=45):
            mark_suspicious(lic, f"PAID_THROUGH_TOO_FAR paid_through={paid_through.isoformat()}")
            premium_final = False

        set_attr_if_exists(lic, "user_id", subscription_id)
        set_attr_if_exists(lic, "last_sync_at", utcnow())

        set_attr_if_exists(lic, "last_payment_time", last_payment_time)
        set_attr_if_exists(lic, "last_payment_amount", (last_payment.get("amount") or {}).get("value"))
        set_attr_if_exists(lic, "last_payment_currency", (last_payment.get("amount") or {}).get("currency_code"))
        set_attr_if_exists(lic, "next_billing_time", next_billing_time)
        set_attr_if_exists(lic, "paid_through", paid_through)

        set_attr_if_exists(lic, "paypal_status", paypal_status_real)

        prev_cancel_requested = bool(get_attr(lic, "cancel_requested", False))
        new_cancel_requested = prev_cancel_requested or (paypal_status_real == "CANCELLED")
        set_attr_if_exists(lic, "cancel_requested", new_cancel_requested)

        if hasattr(lic, "cancel_requested_at"):
            prev_at = get_attr(lic, "cancel_requested_at", None)
            if new_cancel_requested and prev_at is None:
                set_attr_if_exists(lic, "cancel_requested_at", utcnow())

        set_attr_if_exists(lic, "status", "active" if premium_final else "revoked")

        await db.execute(text("SET LOCAL app.verified_write = '1'"))
        await db.commit()
        await db.refresh(lic)

        return build_response(
            lic=lic,
            subscription_id=subscription_id,
            premium=premium_final,
            source="PAYPAL_REFRESH",
            paypal_status_real=paypal_status_real,
            paid_through=paid_through,
        )

    except Exception as e:
        if can_trust_cache(get_attr(lic, "last_sync_at", None), PAYPAL_FAIL_GRACE_HOURS):
            premium_local = compute_premium_from_local(lic)
            return build_response(
                lic=lic,
                subscription_id=subscription_id,
                premium=premium_local,
                source="CACHE_FALLBACK",
                paypal_status_real=None,
                paid_through=get_attr(lic, "paid_through", None),
                warning="PAYPAL_UNAVAILABLE_USING_CACHE",
            )

        raise HTTPException(
            status_code=503,
            detail={
                "msg": "PayPal no disponible y no hay cache confiable. Intenta de nuevo.",
                "error": str(e),
            },
        )
        
def enviar_correo(destinatario: str, key: str, max_devices: str, plan: str, renovacion: str, subscription_id: str):
    # Si quieres usar un link real, define esto arriba o pásalo como parámetro
    APP_OPEN_URL = "https://tu-dominio.com/abrir-luna"  # o luna://open si usas deep link

    HTML_CONTENT = f"""\
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

          <tr>
            <td style="padding:24px;color:#ffffff;">
              <h1 style="margin:0;font-size:22px;letter-spacing:2px;">L U N A</h1>
              <p style="margin:4px 0 0;color:#a9b0c3;font-size:12px;">Licencia &amp; Suscripción</p>
            </td>
          </tr>

          <tr>
            <td style="padding:0 24px 24px;color:#ffffff;">
              <h2 style="font-size:20px;margin:0 0 8px;">¡Gracias por tu compra! 🎉</h2>
              <p style="color:#c7cce0;font-size:14px;line-height:1.6;">
                Tu licencia de <strong>LUNA</strong> ya está activa. Guarda este correo, contiene la información
                necesaria para usar tu app.
              </p>

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

              <div style="margin-top:18px;color:#c7cce0;font-size:14px;line-height:1.6;">
                <strong style="color:#fff;">Cómo activar tu licencia:</strong>
                <ol style="margin:8px 0 0 18px;padding:0;">
                  <li>Abre la aplicación LUNA.</li>
                  <li>Pega tu clave.</li>
                  <li>Dale al botón de activar ahora.</li>
                </ol>
              </div>

              <div style="margin-top:18px;">
                <a href="{APP_OPEN_URL}" style="background:#6d5efc;color:#fff;
                  padding:12px 18px;border-radius:10px;font-size:14px;font-weight:bold;
                  text-decoration:none;display:inline-block;">
                  Abrir LUNA
                </a>
              </div>

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

    # Validación antes de abrir SMTP (mejor)
    if not SMTP_USER or not SMTP_APP_PASSWORD:
        raise RuntimeError("SMTP_USER/SMTP_APP_PASSWORD no configurados")

    msg = EmailMessage()
    msg["Subject"] = "Licencia LUNA | Activación"
    msg["From"] = EMAIL_FROM or SMTP_USER
    msg["To"] = destinatario

    # Texto plano útil (no lo dejes vacío)
    msg.set_content(
        f"Tu licencia LUNA está activa.\n\n"
        f"Clave: {key}\n"
        f"Plan: {plan}\n"
        f"Máx. dispositivos: {max_devices}\n"
        f"Próxima renovación: {renovacion}\n"
        f"Suscripción: {subscription_id}\n"
    )
    msg.add_alternative(HTML_CONTENT, subtype="html")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SMTP_USER, SMTP_APP_PASSWORD)
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
    
# Verificar status del usuario

@app.get("/verify/user")
async def verify_user(
    _=Depends(require_internal_key),

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

        lic.user_id = subscription_id
        lic.paypal_status = paypal_status
        lic.last_payment_time = parse_iso(last_payment.get("time"))
        lic.last_payment_amount = (last_payment.get("amount") or {}).get("value")
        lic.last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")
        lic.next_billing_time = parse_iso(billing_info.get("next_billing_time"))
        lic.last_sync_at = utcnow()

        premium_final, paid_through = compute_premium_window(
            paypal_status=paypal_status,
            last_payment_time=lic.last_payment_time,
            next_billing_time=lic.next_billing_time,
        )

        if hasattr(lic, "paid_through"):
            lic.paid_through = paid_through

        lic.status = "active" if premium_final else "revoked"

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
  
from decimal import Decimal
from datetime import datetime, timezone
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import httpx


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@app.post("/paypal/subscription-capture")
async def paypal_subscription_capture(
    payload: dict,
    db: AsyncSession = Depends(get_db)
):
    license_key = payload.get("license_key")
    if not license_key:
        raise HTTPException(status_code=400, detail="license_key required")

    result = await db.execute(
        select(License).where(License.license_key == license_key)
    )
    lic = result.scalar_one_or_none()

    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    # OJO: aquí uso user_id como subscription_id porque en tu código anterior
    # estabas guardando subscription_id en lic.user_id
    subscription_id = getattr(lic, "subscription_id", None) or getattr(lic, "user_id", None)

    if not subscription_id:
        raise HTTPException(status_code=400, detail="License has no subscription_id")

    token = await get_access_token()

    # 1) Leer suscripción actual
    async with httpx.AsyncClient(timeout=30) as client:
        sub_res = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"}
        )

    if sub_res.status_code >= 400:
        try:
            detail = sub_res.json()
        except Exception:
            detail = {"error": sub_res.text}
        raise HTTPException(status_code=400, detail=detail)

    sub = sub_res.json()
    billing_info = sub.get("billing_info") or {}
    outstanding_balance = billing_info.get("outstanding_balance") or {}
    last_payment = billing_info.get("last_payment") or {}

    outstanding_value_raw = outstanding_balance.get("value")
    outstanding_currency = outstanding_balance.get("currency_code") or "USD"

    try:
        outstanding_value = Decimal(str(outstanding_value_raw or "0"))
    except Exception:
        outstanding_value = Decimal("0")

    # 2) Si no hay saldo pendiente, no hay nada que capturar
    if outstanding_value <= 0:
        # Igual sincronizamos datos locales
        lic.paypal_status = sub.get("status")
        lic.last_payment_time = parse_iso(last_payment.get("time"))
        lic.last_payment_amount = (
            Decimal(str((last_payment.get("amount") or {}).get("value")))
            if (last_payment.get("amount") or {}).get("value") is not None
            else None
        )
        lic.last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")
        lic.next_billing_time = parse_iso(billing_info.get("next_billing_time"))
        lic.last_sync_at = utcnow()
        lic.paid_through = compute_paid_through_monthly(lic.last_payment_time)

        now = utcnow()
        paid_through = lic.paid_through
        lic.status = (
            LicenseStatus.active
            if paid_through is not None and now < paid_through
            else LicenseStatus.revoked
        )

        await db.commit()
        await db.refresh(lic)

        return {
            "ok": False,
            "message": "No outstanding balance to capture",
            "license": {
                "license_key": lic.license_key,
                "status_local": lic.status.value if hasattr(lic.status, "value") else str(lic.status),
                "subscription_id": subscription_id,
                "paid_through": lic.paid_through.isoformat() if lic.paid_through else None,
                "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
                "cancel_requested": lic.cancel_requested,
            },
            "paypal": {
                "status": lic.paypal_status,
                "outstanding_balance": str(outstanding_value),
                "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                "last_payment_currency": lic.last_payment_currency,
                "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
            }
        }

    # 3) Capturar saldo pendiente
    capture_payload = {
        "note": "Manual capture of outstanding subscription balance",
        "capture_type": "OUTSTANDING_BALANCE",
        "amount": {
            "currency_code": outstanding_currency,
            "value": f"{outstanding_value:.2f}"
        }
    }

    async with httpx.AsyncClient(timeout=30) as client:
        cap_res = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}/capture",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=capture_payload,
        )

    if cap_res.status_code >= 400:
        try:
            detail = cap_res.json()
        except Exception:
            detail = {"error": cap_res.text}
        raise HTTPException(status_code=400, detail=detail)

    try:
        capture_data = cap_res.json()
    except Exception:
        capture_data = {"raw": cap_res.text}

    # 4) Refrescar suscripción después del capture
    async with httpx.AsyncClient(timeout=30) as client:
        refresh_res = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"}
        )

    if refresh_res.status_code >= 400:
        try:
            detail = refresh_res.json()
        except Exception:
            detail = {"error": refresh_res.text}
        raise HTTPException(status_code=400, detail=detail)

    fresh = refresh_res.json()
    fresh_billing = fresh.get("billing_info") or {}
    fresh_last_payment = fresh_billing.get("last_payment") or {}

    lic.paypal_status = fresh.get("status")
    lic.last_payment_time = parse_iso(fresh_last_payment.get("time"))
    lic.last_payment_amount = (
        Decimal(str((fresh_last_payment.get("amount") or {}).get("value")))
        if (fresh_last_payment.get("amount") or {}).get("value") is not None
        else None
    )
    lic.last_payment_currency = (fresh_last_payment.get("amount") or {}).get("currency_code")
    lic.next_billing_time = parse_iso(fresh_billing.get("next_billing_time"))
    lic.last_sync_at = utcnow()
    lic.cancel_requested = False

    # paid_through SOLO desde pago real
    lic.paid_through = compute_paid_through_monthly(lic.last_payment_time)

    now = utcnow()
    paid_through = lic.paid_through
    lic.status = (
        LicenseStatus.active
        if paid_through is not None and now < paid_through
        else LicenseStatus.revoked
    )

    await db.commit()
    await db.refresh(lic)

    return {
        "ok": True,
        "capture_response": capture_data,
        "license": {
            "license_key": lic.license_key,
            "status_local": lic.status.value if hasattr(lic.status, "value") else str(lic.status),
            "subscription_id": subscription_id,
            "paid_through": lic.paid_through.isoformat() if lic.paid_through else None,
            "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
            "cancel_requested": lic.cancel_requested,
        },
        "paypal": {
            "status": lic.paypal_status,
            "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
            "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
            "last_payment_currency": lic.last_payment_currency,
            "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
        }
    }