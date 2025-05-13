from datetime import datetime
from typing import Optional
from bson import ObjectId
from pydantic import BaseModel, Field, validator
from ..utils.logger import get_logger
import re

logger = get_logger(__name__)

class PasswordBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    url: Optional[str] = None
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)
    category: str = Field(default="Login")
    notes: Optional[str] = None

    @validator('url')
    def validate_url(cls, v):
        if v is None or v == "":
            return None
        # Enhanced URL validation
        url_pattern = re.compile(
            r'^(https?|ftp):\/\/'  # protocols
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domains
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)'  # TLD
            r'|localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # OR ip address
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$',  # path/query
            re.IGNORECASE
        )
        if not re.match(url_pattern, v):
            raise ValueError('Invalid URL format. Must start with http://, https://, or ftp://')
        return v

class PasswordCreate(PasswordBase):
    pass

class PasswordInDB(PasswordBase):
    id: str = Field(..., alias="_id")  # MongoDB _id is mapped to 'id'
    owner_email: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            ObjectId: str  # Convert ObjectId to string here
        }
        populate_by_name = True  # Allow both id and _id