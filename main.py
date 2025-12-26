from datetime import datetime, timedelta, timezone
from typing import Dict, List
import secrets

import jwt
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

app = FastAPI(title="LUNA Licensing API")

# =========================
# CONFIG
# =========================
JWT_SECRET = "CAMBIA_ESTA_CLAVE_SUPER_SECRETA"
JWT_ALG = "HS256"
ACCESS_MINUTES = 15  # Access token corto (se renueva con refresh)

# =========================
# "DB" EN MEMORIA (DEMO)
# En prod: PostgreSQL
# =========================
LICENSES: Dict[str, Dict] = {
    "LUNA-AAAA-BBBB-CCCC": {"active": True, "max_devices": 1, "devices": []},
    "LUNA-1111-2222-3333": {"active": True, "max_devices": 2, "devices": []},
}

# refresh_store: refreshToken -> {licenseKey, deviceId}
REFRESH_STORE: Dict[str, Dict] = {}

# =========================
# MODELOS
# =========================
class ActivateRequest(BaseModel):
    licenseKey: str = Field(..., min_length=5)
    deviceId: str = Field(..., min_length=16)

class ActivateResponse(BaseModel):
    accessToken: str
    refreshToken: str

class ValidateRequest(BaseModel):
    deviceId: str = Field(..., min_length=16)

class RefreshRequest(BaseModel):
    refreshToken: str = Field(..., min_length=10)
    deviceId: str = Field(..., min_length=16)

class RefreshResponse(BaseModel):
    accessToken: str
    refreshToken: str

# =========================
# HELPERS
# =========================
def issue_access_token(license_key: str, device_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "luna_access",
        "licenseKey": license_key,
        "deviceId": device_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def issue_refresh_token() -> str:
    # token aleatorio fuerte
    return secrets.token_urlsafe(48)

def ensure_license_ok(license_key: str, device_id: str):
    lic = LICENSES.get(license_key)
    if not lic:
        raise HTTPException(status_code=401, detail="Licencia inválida")
    if not lic["active"]:
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    devices: List[str] = lic["devices"]

    # si no existe el deviceId aún, intenta registrar
    if device_id not in devices:
        if len(devices) >= lic["max_devices"]:
            raise HTTPException(status_code=409, detail="Límite de dispositivos alcanzado")
        devices.append(device_id)

# =========================
# ENDPOINTS
# =========================
@app.post("/activate", response_model=ActivateResponse)
def activate(req: ActivateRequest):
    # 1) valida licencia + registra device si aplica
    ensure_license_ok(req.licenseKey, req.deviceId)

    # 2) emite access
    access = issue_access_token(req.licenseKey, req.deviceId)

    # 3) refresh "de por vida" por dispositivo:
    #    Si ya existe un refresh para ese device+license, reutilízalo.
    #    Si no existe, crea uno nuevo.
    existing_refresh = None
    for rt, data in REFRESH_STORE.items():
        if data["licenseKey"] == req.licenseKey and data["deviceId"] == req.deviceId:
            existing_refresh = rt
            break

    if existing_refresh:
        refresh = existing_refresh
    else:
        refresh = issue_refresh_token()
        REFRESH_STORE[refresh] = {
            "licenseKey": req.licenseKey,
            "deviceId": req.deviceId,
        }

    return {"accessToken": access, "refreshToken": refresh}


@app.post("/validate")
def validate(req: ValidateRequest, authorization: str = Header(default="")):
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

    # valida licencia aún activa
    lic_key = payload.get("licenseKey")
    lic = LICENSES.get(lic_key)
    if not lic or not lic["active"]:
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    return {"ok": True}


@app.post("/refresh", response_model=RefreshResponse)
def refresh(req: RefreshRequest):
    rec = REFRESH_STORE.get(req.refreshToken)
    if not rec:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

    # device binding
    if rec["deviceId"] != req.deviceId:
        raise HTTPException(status_code=401, detail="Refresh token no pertenece a este dispositivo")

    # valida licencia aún activa (y que el dispositivo siga autorizado)
    ensure_license_ok(rec["licenseKey"], rec["deviceId"])

    # genera nuevo access token
    new_access = issue_access_token(rec["licenseKey"], rec["deviceId"])

    # refresh de por vida: se devuelve el mismo
    return {"accessToken": new_access, "refreshToken": req.refreshToken}
