from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from db import get_db
from models import License, LicenseDevice, PaypalSubscription, LicenseStatus
from schemas import RestoreByLicenseBody, DeactivateDeviceBody

router = APIRouter()

def now_utc():
    return datetime.now(timezone.utc)

@router.post("/license/restore")
async def restore_by_license(body: RestoreByLicenseBody, db: AsyncSession = Depends(get_db)):
    # 1) Busca licencia por key
    q = await db.execute(
        select(License).where(License.license_key == body.license_key).limit(1)
    )
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    # 2) Estado local rápido
    if lic.status != LicenseStatus.active:
        raise HTTPException(status_code=403, detail=f"Licencia no activa ({lic.status})")

    # 3) Verifica que la licencia esté ligada a una suscripción
    if not lic.paypal_subscription_db_id:
        raise HTTPException(status_code=409, detail="Licencia no está ligada a una suscripción")

    sub = await db.get(PaypalSubscription, lic.paypal_subscription_db_id)
    if not sub:
        raise HTTPException(status_code=409, detail="Suscripción ligada no existe en DB")

    # 4) Valida suscripción local
    # (si quieres robustez: aquí puedes llamar a PayPal y sincronizar status)
    if sub.status not in ("ACTIVE", "APPROVED"):  # ajusta si usas otro mapping
        raise HTTPException(status_code=403, detail=f"Suscripción no activa ({sub.status})")

    # 5) Manejo de dispositivos: registra esta PC si hay cupo
    # ¿ya existe este device?
    qd = await db.execute(
        select(LicenseDevice).where(
            LicenseDevice.license_id == lic.id,
            LicenseDevice.device_id == body.device_id,
        ).limit(1)
    )
    device_row = qd.scalar_one_or_none()

    if device_row:
        # Si estaba revocado, lo “reactivas” (opcional)
        device_row.revoked_at = None
        device_row.last_seen_at = now_utc()
        await db.commit()
        return {
            "ok": True,
            "license_status": lic.status,
            "subscription_status": sub.status,
            "device": "known",
            "max_devices": lic.max_devices,
        }

    # cuenta dispositivos activos
    qc = await db.execute(
        select(func.count()).select_from(LicenseDevice).where(
            and_(
                LicenseDevice.license_id == lic.id,
                LicenseDevice.revoked_at.is_(None),
            )
        )
    )
    active_count = int(qc.scalar_one())

    if active_count >= lic.max_devices:
        # Política: NO autorizar y pedir liberar uno
        raise HTTPException(
            status_code=409,
            detail=f"Se alcanzó el máximo de dispositivos ({lic.max_devices}). Desactiva uno para continuar."
        )

    # inserta nuevo device
    new_dev = LicenseDevice(
        license_id=lic.id,
        device_id=body.device_id,
        revoked_at=None,
        last_seen_at=now_utc(),
    )
    db.add(new_dev)
    await db.commit()

    return {
        "ok": True,
        "license_status": lic.status,
        "subscription_status": sub.status,
        "device": "added",
        "max_devices": lic.max_devices,
    }


@router.post("/license/deactivate-device")
async def deactivate_device(body: DeactivateDeviceBody, db: AsyncSession = Depends(get_db)):
    # Busca licencia
    q = await db.execute(select(License).where(License.license_key == body.license_key).limit(1))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    # Busca device
    qd = await db.execute(
        select(LicenseDevice).where(
            LicenseDevice.license_id == lic.id,
            LicenseDevice.device_id == body.device_id,
            LicenseDevice.revoked_at.is_(None),
        ).limit(1)
    )
    dev = qd.scalar_one_or_none()
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado o ya desactivado")

    dev.revoked_at = now_utc()
    dev.last_seen_at = now_utc()
    await db.commit()

    return {"ok": True, "msg": "Dispositivo desactivado"}