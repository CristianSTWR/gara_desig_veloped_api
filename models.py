# models.py
from sqlalchemy import JSON
from datetime import datetime
from sqlalchemy import (
    Boolean, DateTime, Integer, String, Numeric, Enum, 
    ForeignKey, UniqueConstraint, func, text, BigInteger, Text
)
import enum
import uuid
from sqlalchemy.dialects.postgresql import UUID
from enum import Enum as PyEnum
from sqlalchemy.orm import relationship, Mapped, mapped_column
from db import Base
from sqlalchemy.dialects.postgresql import JSONB

class LicenseStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"

class License(Base):
    __tablename__ = "licenses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    user_id: Mapped[str] = mapped_column(String(128), nullable=False)

    license_key: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True
    )
    
    suspicious: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,                # ORM
        server_default=text("false")  # DB
    )

    suspicious_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    status: Mapped[LicenseStatus] = mapped_column(
        Enum(LicenseStatus, name="license_status"),
        nullable=False,
        server_default=text("'active'")
    )

    max_devices: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("1")
    )

    expires_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --------------------
    # PayPal / Billing
    # --------------------

    paypal_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    last_payment_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    last_payment_amount: Mapped[float | None] = mapped_column(
        Numeric(12, 2),
        nullable=True
    )

    last_payment_currency: Mapped[str | None] = mapped_column(
        String(8),
        nullable=True
    )

    next_billing_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    last_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    cancel_requested: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,                 # ORM
        server_default=text("false")   # DB
    )

    # ✅ NUEVO: hasta cuándo tiene acceso premium
    paid_through: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # ✅ NUEVO: cuándo se detectó la cancelación
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # --------------------
    # Relationships
    # --------------------

    devices: Mapped[list["LicenseDevice"]] = relationship(
        "LicenseDevice",
        back_populates="license",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="license",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

class LicenseDevice(Base):
    __tablename__ = "license_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ✅ FK correcto: licenses.license_key
    license_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="CASCADE"),
        nullable=False
    )

    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    license: Mapped["License"] = relationship("License", back_populates="devices")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_license_device"),
    )


class PaypalEnv(PyEnum):
    sandbox = "sandbox"
    live = "live"


class Planes(Base):
    __tablename__ = "billing_plan"

    # PK
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    # Entorno PayPal
    env: Mapped[PaypalEnv] = mapped_column(
        Enum(PaypalEnv, name="paypal_env"),
        nullable=False
    )

    # Clave interna (premium_monthly, premium_yearly, etc.)
    plan_key: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    # Nombre visible (LUNA Premium Mensual)
    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False
    )

    # Moneda (USD)
    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False
    )

    # Precio (24.99)
    price: Mapped[float] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    # IDs PayPal
    paypal_product_id: Mapped[str] = mapped_column(
        String(40),
        nullable=False
    )

    paypal_plan_id: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        unique=True
    )

    # Activo / inactivo
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True
    )

    # Fechas
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<Plan id={self.id} key={self.plan_key} "
            f"price={self.price} {self.currency} env={self.env}>"
        )

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    token: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)

    # ✅ FK correcto: licenses.license_key
    license_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="CASCADE"),
        nullable=False
    )

    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    license: Mapped["License"] = relationship("License", back_populates="refresh_tokens")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_refresh_per_install"),
    )
    
class PaypalSubscription(Base):
    __tablename__ = "paypal_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    env: Mapped[PaypalEnv] = mapped_column(
        Enum(PaypalEnv, name="paypal_env"),
        nullable=False
    )

    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    paypal_plan_id: Mapped[str] = mapped_column(String(64), nullable=False)

    paypal_subscription_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="CREATED")
    approve_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    subscriber_email = mapped_column(String) 

    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
class PaypalWebhookEvent(Base):
    __tablename__ = "paypal_webhook_event"

    __table_args__ = (
        UniqueConstraint("env", "paypal_event_id", name="uq_webhook_env_event"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    env: Mapped[PaypalEnv] = mapped_column(
        Enum(PaypalEnv, name="paypal_env"),
        nullable=False
    )

    paypal_event_id: Mapped[str] = mapped_column(Text, nullable=False)  # body["id"]
    event_type: Mapped[str] = mapped_column(Text, nullable=False)

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    processing_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=text("'received'")  # received|processed|failed
    )

    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
