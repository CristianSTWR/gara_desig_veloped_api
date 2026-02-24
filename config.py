import os
from dotenv import load_dotenv

load_dotenv()

def _get(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name, default)
    if v is None:
        return None
    v = v.strip()
    return v if v != "" else default

APP_ENV = (_get("APP_ENV", "local") or "local").lower()  # local | prod
IS_PROD = APP_ENV == "prod"

# Security / JWT
JWT_SECRET = _get("JWT_SECRET")
JWT_ALGORITHM = _get("JWT_ALGORITHM", "HS256") or "HS256"
ACCESS_MINUTES = int(_get("ACCESS_MINUTES", "15") or "15")
REFRESH_DAYS = int(_get("REFRESH_DAYS", "60") or "60")

# Database
DATABASE_URL = _get("DATABASE_URL")

# PayPal
PAYPAL_BASE_URL = _get("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
PAYPAL_CLIENT_ID = _get("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = _get("PAYPAL_CLIENT_SECRET")
PAYPAL_RETURN_URL = _get("PAYPAL_RETURN_URL")  # set in env
PAYPAL_CANCEL_URL = _get("PAYPAL_CANCEL_URL")  # set in env
PAYPAL_WEBHOOK_ID = _get("PAYPAL_WEBHOOK_ID")  # set in env
VERIFY_PAYPAL_WEBHOOKS = (_get("VERIFY_PAYPAL_WEBHOOKS", "true") or "true").lower() == "true"

# Email (SMTP)
SMTP_HOST = _get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(_get("SMTP_PORT", "465") or "465")
SMTP_USER = _get("SMTP_USER")
SMTP_APP_PASSWORD = _get("SMTP_APP_PASSWORD")
EMAIL_FROM = _get("EMAIL_FROM", SMTP_USER or "")

# CORS / Hosts
# comma-separated lists
ALLOWED_ORIGINS = [o.strip() for o in (_get("ALLOWED_ORIGINS", "") or "").split(",") if o.strip()]
ALLOWED_HOSTS = [h.strip() for h in (_get("ALLOWED_HOSTS", "") or "").split(",") if h.strip()]

# Request limits
MAX_BODY_BYTES = int(_get("MAX_BODY_BYTES", "1048576") or "1048576")  # 1MB default

def validate_settings():
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET no está definido en el entorno")
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL no está definida en el entorno")
    if IS_PROD:
        # Require these in production to avoid ngrok defaults
        if not PAYPAL_RETURN_URL or not PAYPAL_CANCEL_URL:
            raise RuntimeError("En producción define PAYPAL_RETURN_URL y PAYPAL_CANCEL_URL")
