from datetime import datetime, timedelta, timezone
from typing import Dict, List

import secrets
import jwt
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

app = FastAPI(title="LUNA Licensing API")

JWT_SECRET = "CAMBIA_ESTA_CLAVE_SUPER_SECRETA"
JWT_ALG = "HS256"
ACCESS_MINUTES = 15

LICENSES: Dict[str, Dict] = {
    "LUNA-AAAA-BBBB-CCCC": {"active": False, "max_devices": 1, "devices": []},
    "LUNA-1111-2222-3333": {"active": True, "max_devices": 2, "devices": []},
}

# refreshToken -> {licenseKey, deviceId}
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
# HELPERS (1 sola versión)
# =========================
def ensure_license_ok(licenseKey: str, deviceId: str) -> None:
    lic = LICENSES.get(licenseKey)
    if not lic:
        raise HTTPException(status_code=401, detail="Licencia inválida")
    if not lic.get("active"):
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    devices: List[str] = lic.setdefault("devices", [])
    if deviceId not in devices:
        if len(devices) >= int(lic.get("max_devices", 1)):
            raise HTTPException(status_code=409, detail="Límite de dispositivos alcanzado")
        devices.append(deviceId)

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

# =========================
# ENDPOINTS
# =========================
@app.post("/activate", response_model=ActivateResponse)
def activate(req: ActivateRequest):
    ensure_license_ok(req.licenseKey, req.deviceId)

    access = issue_access_token(req.licenseKey, req.deviceId)

    # refresh "por instalación": reutiliza si ya existe
    for rt, data in REFRESH_STORE.items():
        if data["licenseKey"] == req.licenseKey and data["deviceId"] == req.deviceId:
            return {"accessToken": access, "refreshToken": rt}

    refresh = issue_refresh_token()
    REFRESH_STORE[refresh] = {"licenseKey": req.licenseKey, "deviceId": req.deviceId}
    return {"accessToken": access, "refreshToken": refresh}

@app.post("/refresh", response_model=RefreshResponse)
def refresh(req: RefreshRequest):
    rec = REFRESH_STORE.get(req.refreshToken)
    if not rec:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

    if rec["deviceId"] != req.deviceId:
        raise HTTPException(status_code=401, detail="Refresh token no pertenece a este dispositivo")

    ensure_license_ok(rec["licenseKey"], rec["deviceId"])

    new_access = issue_access_token(rec["licenseKey"], rec["deviceId"])
    return {"accessToken": new_access, "refreshToken": req.refreshToken}

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

    lic_key = payload.get("licenseKey")
    lic = LICENSES.get(lic_key)
    if not lic or not lic.get("active"):
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    return {"ok": True}
