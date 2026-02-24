# models.py
from datetime import datetime
from sqlalchemy import (
    Boolean, DateTime, Integer, String,
    ForeignKey, UniqueConstraint, func
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from db import Base


class License(Base):
    __tablename__ = "licenses"

    # Ej: "LUNA-AAAA-BBBB-CCCC"
    key: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)

    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Si es None => no expira
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    devices = relationship("LicenseDevice", back_populates="license", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="license", cascade="all, delete-orphan")


class LicenseDevice(Base):
    __tablename__ = "license_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    license_key: Mapped[str] = mapped_column(String(64), ForeignKey("licenses.key", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    license = relationship("License", back_populates="devices")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_license_device"),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    token: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)  # secrets.token_urlsafe(48) cabe bien
    license_key: Mapped[str] = mapped_column(String(64), ForeignKey("licenses.key", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)

    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    license = relationship("License", back_populates="refresh_tokens")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_refresh_per_install"),
    )
