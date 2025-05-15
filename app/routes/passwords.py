from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime
from typing import List, Optional
import motor.motor_asyncio
from bson import ObjectId
from dotenv import load_dotenv
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

from ..models.password import PasswordCreate, PasswordInDB
from ..models.user import UserInDB
from ..utils.security import decode_token
from ..utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

router = APIRouter(
    prefix="/passwords",
    tags=["passwords"],
    responses={
        404: {"description": "Not found"},
        401: {"description": "Unauthorized"},
        400: {"description": "Bad request"}
    },
)

security = HTTPBearer()

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client.get_database("password_manager")
passwords_collection = db.get_collection("passwords")

# AES-256-GCM Encryption setup
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    logger.error("ENCRYPTION_KEY not found in environment variables")
    raise ValueError("ENCRYPTION_KEY environment variable not set")

# Ensure key is 32 bytes for AES-256
key = ENCRYPTION_KEY.encode().ljust(32)[:32]

def encrypt_password(password: str) -> dict:
    """Encrypt password using AES-256-GCM"""
    try:
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(encryptor.tag).decode(),
            "version": "aes_gcm_v1"
        }
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt password"
        )

def decrypt_password(encrypted_data: dict) -> str:
    """Decrypt password using AES-256-GCM"""
    try:
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        iv = base64.b64decode(encrypted_data["iv"])
        tag = base64.b64decode(encrypted_data["tag"])
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt password"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Get current user email from JWT token"""
    try:
        payload = decode_token(credentials.credentials)
        if not (email := payload.get("sub")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return email
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

@router.post("/", response_model=PasswordInDB, status_code=status.HTTP_201_CREATED)
async def create_password(
    password: PasswordCreate,
    email: str = Depends(get_current_user)
):
    """Create a new password entry"""
    try:
        encrypted = encrypt_password(password.password)
        password_dict = password.dict()
        password_dict.update({
            "password": encrypted,
            "owner_email": email,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })
        
        result = await passwords_collection.insert_one(password_dict)
        new_password = await passwords_collection.find_one({"_id": result.inserted_id})
        new_password["_id"] = str(new_password["_id"])
        return PasswordInDB(**new_password)
        
    except Exception as e:
        logger.error(f"Error creating password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating password"
        )

@router.get("/", response_model=List[PasswordInDB])
async def get_passwords(
    email: str = Depends(get_current_user),
    category: Optional[str] = None,
    search: Optional[str] = None
):
    """Get all passwords for current user"""
    try:
        query = {"owner_email": email}
        if category: query["category"] = category
        if search: query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"username": {"$regex": search, "$options": "i"}},
            {"url": {"$regex": search, "$options": "i"}}
        ]
        
        passwords = []
        async for doc in passwords_collection.find(query).sort("title"):
            try:
                if isinstance(doc["password"], dict):  # New AES format
                    doc["password"] = decrypt_password(doc["password"])
                doc["_id"] = str(doc["_id"])
                passwords.append(PasswordInDB(**doc))
            except Exception as e:
                logger.error(f"Failed to process password {doc.get('_id')}: {str(e)}")
                continue
                
        return passwords
    except Exception as e:
        logger.error(f"Error fetching passwords: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error fetching passwords"
        )

@router.put("/{password_id}", response_model=PasswordInDB)
async def update_password(
    password_id: str,
    password: PasswordCreate,
    email: str = Depends(get_current_user)
):
    """Update a password entry"""
    try:
        try:
            obj_id = ObjectId(password_id)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password ID format"
            )
            
        existing = await passwords_collection.find_one({
            "_id": obj_id,
            "owner_email": email
        })
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Password not found"
            )
        
        update_data = password.dict()
        update_data.update({
            "password": encrypt_password(password.password),
            "updated_at": datetime.utcnow()
        })
        
        result = await passwords_collection.update_one(
            {"_id": obj_id},
            {"$set": update_data}
        )
        if result.modified_count != 1:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )
            
        updated = await passwords_collection.find_one({"_id": obj_id})
        updated["_id"] = str(updated["_id"])
        return PasswordInDB(**updated)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating password"
        )

@router.delete("/{password_id}")
async def delete_password(
    password_id: str,
    email: str = Depends(get_current_user)
):
    """Delete a password entry"""
    try:
        try:
            obj_id = ObjectId(password_id)
        except:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password ID format"
            )
            
        existing = await passwords_collection.find_one({
            "_id": obj_id,
            "owner_email": email
        })
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Password not found"
            )
        
        result = await passwords_collection.delete_one({"_id": obj_id})
        if result.deleted_count != 1:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete password"
            )
            
        return {"message": "Password deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting password"
        )