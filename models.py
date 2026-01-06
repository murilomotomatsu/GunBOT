from pydantic import BaseModel

class ValidateRequest(BaseModel):
    key: str
    hwid: str
    version: str

class ValidateResponse(BaseModel):
    status: str
