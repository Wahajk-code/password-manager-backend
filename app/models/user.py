from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
from ..utils.logger import get_logger

logger = get_logger(__name__)

class UserBase(BaseModel):
    email: EmailStr
    username: str
    disabled: Optional[bool] = False

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserInDB(UserBase):
    # Add this configuration to handle MongoDB's _id field
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    id: Optional[str] = None
    hashed_password: str
    created_at: datetime
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False

    # Add this class method to handle the _id to id conversion
    @classmethod
    def from_mongo(cls, data: dict):
        if not data:
            return data
        id = data.pop('_id', None)
        return cls(**dict(data, id=str(id)))

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerification(BaseModel):
    mfa_code: str = Field(..., min_length=6, max_length=6, example="123456")
    email: EmailStr  # Make sure this matches exactly what your frontend sends