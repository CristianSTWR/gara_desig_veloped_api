
from sqlalchemy import JSON
from datetime import datetime
from sqlalchemy import (
    Boolean, DateTime, Integer, String, Numeric, Enum,
    ForeignKey, UniqueConstraint, func, text
)
import enum
import uuid
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
        server_default=text("'active'")
    )
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    expires_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)
