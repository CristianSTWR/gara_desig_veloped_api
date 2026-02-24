
# main.py — FIXED ACTIVATION ISSUES

from datetime import datetime, timedelta, timezone
import os
import secrets
import hashlib
import uuid
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header
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
    raise RuntimeError("JWT_SECRET no está definido")

app = FastAPI(title="LUNA Licensing API")

# =========================
# MODELOS REQUEST/RESPONSE
# =========================
class ActivateRequest(BaseModel):
    licenseKey: str = Field(..., min_length=5)
    # FIX: bajar mínimo para evitar 422 por deviceId corto
    deviceId: str = Field(..., min_length=8)

class ActivateResponse(BaseModel):
    accessToken: str
    refreshToken: str

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

    # FIX: normalizar status (enum/string)
    if str(lic["status"]).lower() != "active":
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    # FIX: comparación UTC segura
    if lic["expires_at"] is not None:
        exp = lic["expires_at"]
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= exp:
            raise HTTPException(status_code=403, detail="Licencia expirada")

    return str(lic["id"])

async def create_refresh_session(db: AsyncSession, license_id: str, deviceId: str) -> str:
    refresh = issue_refresh_token()
    r_hash = sha256_hex(refresh)

    await db.execute(
        text("""
            INSERT INTO license_sessions
              (id, license_id, device_id, refresh_token_hash, issued_at, expires_at, revoked)
            VALUES
              (:id, :lid, :did, :h, NOW(), NOW() + (:days * INTERVAL '1 day'), FALSE)
        """),
        {"id": str(uuid.uuid4()), "lid": license_id, "did": deviceId, "h": r_hash, "days": REFRESH_DAYS},
    )
    await db.commit()
    return refresh

# =========================
# ENDPOINTS
# =========================
@app.post("/activate", response_model=ActivateResponse)
async def activate(req: ActivateRequest, db: AsyncSession = Depends(get_db)):
    license_id = await ensure_license_ok(db, req.licenseKey, req.deviceId)
    access = issue_access_token(req.licenseKey, req.deviceId)
    refresh = await create_refresh_session(db, license_id, req.deviceId)
    return {"accessToken": access, "refreshToken": refresh}
