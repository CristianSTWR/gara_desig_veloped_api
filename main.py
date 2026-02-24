# main.py (PostgreSQL + SQLAlchemy AsyncSession) — REPARADO

from datetime import datetime, timedelta, timezone
import os
import secrets
import hashlib
import uuid

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from db import get_db

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALG = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_MINUTES = int(os.getenv("ACCESS_MINUTES", "15"))
REFRESH_DAYS = int(os.getenv("REFRESH_DAYS", "60"))

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET no está definido en el entorno")

app = FastAPI(title="LUNA Licensing API")

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
    if lic["status"] != "active":
        raise HTTPException(status_code=403, detail="Licencia desactivada")

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
    license_id = await ensure_license_ok(db, req.licenseKey, req.deviceId)
    access = issue_access_token(req.licenseKey, req.deviceId)
    refresh = await create_refresh_session(db, license_id, req.deviceId)
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
