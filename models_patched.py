# models.py
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Numeric,
    Enum,
    ForeignKey,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column

from db import Base


class LicenseStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    license_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    status: Mapped[LicenseStatus] = mapped_column(
        Enum(LicenseStatus, name="license_status"),
        nullable=False,
        server_default=text("'active'"),
    )

    max_devices: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # 🔥 Ligadura permanente a PayPal (para restaurar desde otra PC por licencia)
    paypal_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    paypal_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)

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

    license_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    device_id: Mapped[str] = mapped_column(String(128), nullable=False)

    first_activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))

    license: Mapped["License"] = relationship("License", back_populates="devices")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_license_device"),
    )


class PaypalEnv(PyEnum):
    sandbox = "sandbox"
    live = "live"


class Planes(Base):
    __tablename__ = "billing_plan"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    env: Mapped[PaypalEnv] = mapped_column(Enum(PaypalEnv, name="paypal_env"), nullable=False)

    plan_key: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    price: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)

    paypal_product_id: Mapped[str] = mapped_column(String(40), nullable=False)
    paypal_plan_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self) -> str:
        return f"<Plan id={self.id} key={self.plan_key} price={self.price} {self.currency} env={self.env}>"


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    token: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)

    license_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    license: Mapped["License"] = relationship("License", back_populates="refresh_tokens")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_refresh_per_install"),
    )


class PaypalSubscription(Base):
    __tablename__ = "paypal_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    env: Mapped[PaypalEnv] = mapped_column(Enum(PaypalEnv, name="paypal_env"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    paypal_plan_id: Mapped[str] = mapped_column(String(64), nullable=False)

    paypal_subscription_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="CREATED")
    approve_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # 🔥 Ligadura a licencia: restaurar por licencia
    license_key: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
