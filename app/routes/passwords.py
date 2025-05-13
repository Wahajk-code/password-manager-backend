from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime
from typing import List, Optional
import motor.motor_asyncio
from bson import ObjectId
from dotenv import load_dotenv
import os
from cryptography.fernet import Fernet

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

# Encryption setup
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    logger.error("ENCRYPTION_KEY not found in environment variables")
    raise ValueError("ENCRYPTION_KEY environment variable not set")

try:
    fernet = Fernet(ENCRYPTION_KEY.encode())
except Exception as e:
    logger.error(f"Failed to initialize Fernet: {str(e)}")
    raise

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

def encrypt_password(password: str) -> str:
    """Encrypt password using Fernet"""
    try:
        return fernet.encrypt(password.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt password"
        )

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt password using Fernet"""
    try:
        return fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt password"
        )
    


@router.post("/", response_model=PasswordInDB, status_code=status.HTTP_201_CREATED)
async def create_password(
    password: PasswordCreate,
    email: str = Depends(get_current_user)
):
    """Create a new password entry"""
    try:
        # Prepare document for MongoDB
        password_dict = password.dict()
        password_dict.update({
            "password": encrypt_password(password.password),
            "owner_email": email,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })
        
        # Insert into MongoDB
        result = await passwords_collection.insert_one(password_dict)
        if not result.inserted_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create password"
            )
            
        # Return the created document
        new_password = await passwords_collection.find_one({"_id": result.inserted_id})
        if not new_password:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve created password"
            )
        
        # Convert ObjectId to string and return
        new_password["_id"] = str(new_password["_id"])
        return PasswordInDB(**new_password)
        
    except HTTPException:
        raise
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
        if category:
            query["category"] = category
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"username": {"$regex": search, "$options": "i"}},
                {"url": {"$regex": search, "$options": "i"}}
            ]
        
        passwords = []
        async for doc in passwords_collection.find(query).sort("title"):
            try:
                doc["password"] = decrypt_password(doc["password"])
                # Manually convert ObjectId to string
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
        # Verify ObjectId format
        try:
            obj_id = ObjectId(password_id)  # Convert password_id to ObjectId
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password ID format"
            )
            
        # Verify ownership
        existing = await passwords_collection.find_one({
            "_id": obj_id,
            "owner_email": email
        })
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Password not found"
            )
        
        # Prepare update
        update_data = password.dict()
        update_data.update({
            "password": encrypt_password(password.password),
            "updated_at": datetime.utcnow()
        })
        
        # Perform update
        result = await passwords_collection.update_one(
            {"_id": obj_id},
            {"$set": update_data}
        )
        if result.modified_count != 1:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )
            
        # Return updated document and ensure _id is converted to string
        updated = await passwords_collection.find_one({"_id": obj_id})
        updated["_id"] = str(updated["_id"])  # Convert ObjectId to string
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
        # Verify ObjectId format
        try:
            obj_id = ObjectId(password_id)
        except:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password ID format"
            )
            
        # Verify ownership
        existing = await passwords_collection.find_one({
            "_id": obj_id,
            "owner_email": email
        })
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Password not found"
            )
        
        # Perform deletion
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