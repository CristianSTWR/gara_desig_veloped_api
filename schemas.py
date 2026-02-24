from pydantic import BaseModel, Field

class RestoreByLicenseBody(BaseModel):
    license_key: str = Field(..., min_length=5, max_length=80)
    device_id: str = Field(..., min_length=3, max_length=128)

class DeactivateDeviceBody(BaseModel):
    license_key: str
    device_id: str