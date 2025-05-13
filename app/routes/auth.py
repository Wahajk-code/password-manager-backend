from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated, Optional
import motor.motor_asyncio
from dotenv import load_dotenv
from pydantic import BaseModel
import os

from ..models.user import (
    UserCreate,
    UserInDB,
    Token,
    UserLogin,
    OTPRequest,
    OTPVerification
)
from ..utils.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_token,
    ACCESS_TOKEN_EXPIRE_MINUTES  # This needs to be imported from security.py
)

security = HTTPBearer()

# Add this model to your auth.py file
class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


from ..utils.otp import OTPManager
from ..utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={401: {"description": "Unauthorized"}},
)



# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    logger.error("MONGO_URI not found in environment variables")
    raise ValueError("MONGO_URI environment variable not set")

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client.get_database("auth_db")
users_collection = db.get_collection("users")

otp_manager = OTPManager()


@router.post("/change-password", response_model=dict)
async def change_password(
    password_change: PasswordChangeRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Change user's password after verifying current password.
    
    Requirements:
    - Valid JWT token in Authorization header
    - Current password must match stored hash
    - New password must be at least 8 characters
    """
    try:
        # Decode token to get user email
        token = credentials.credentials
        payload = decode_token(token)
        email = payload.get("sub")
        
        if not email:
            logger.warning("Invalid token payload in password change request")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        logger.info(f"Password change request for user: {email}")

        # Get user from database
        user = await get_user(email)
        if not user:
            logger.warning(f"User not found: {email}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Verify current password using security utils
        if not verify_password(password_change.current_password, user.hashed_password):
            logger.warning(f"Current password verification failed for user: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )

        # Hash new password using security utils
        new_hashed_password = get_password_hash(password_change.new_password)

        # Update password in database
        update_result = await users_collection.update_one(
            {"email": email},
            {"$set": {"hashed_password": new_hashed_password}}
        )

        if update_result.modified_count != 1:
            logger.error(f"Password update failed for user: {email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )

        logger.info(f"Password successfully updated for user: {email}")
        return {"message": "Password updated successfully"}

    except HTTPException as he:
        logger.error(f"HTTPException in password change: {str(he.detail)}")
        raise he
    except Exception as e:
        logger.error(f"Unexpected error in password change: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred"
        )
    

    
async def get_user(email: str) -> Optional[UserInDB]:
    """Get user from database by email"""
    try:
        user_data = await users_collection.find_one({"email": email})
        if user_data:
            return UserInDB.from_mongo(user_data)  # Use the from_mongo method
        return None
    except Exception as e:
        logger.error(f"Error fetching user {email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

async def authenticate_user(email: str, password: str) -> Optional[UserInDB]:
    """Authenticate user with email and password"""
    logger.info(f"Attempting to authenticate user: {email}")
    user = await get_user(email)
    if not user:
        logger.warning(f"User not found: {email}")
        return None
    if not verify_password(password, user.hashed_password):
        logger.warning(f"Invalid password for user: {email}")
        return None
    logger.info(f"User authenticated successfully: {email}")
    return user

async def create_user(user: UserCreate) -> UserInDB:
    """Create a new user in the database"""
    logger.info(f"Creating new user: {user.email}")
    
    # Check if user already exists
    existing_user = await get_user(user.email)
    if existing_user:
        logger.warning(f"User already exists: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Create user document
    user_dict = {
        "email": user.email,
        "username": user.username,
        "hashed_password": hashed_password,
        "disabled": False,
        "created_at": datetime.utcnow(),
        "mfa_enabled": True
    }
    
    try:
        result = await users_collection.insert_one(user_dict)
        if result.inserted_id:
            # Get the newly created user with proper ID conversion
            new_user = await get_user(user.email)
            logger.info(f"User created successfully: {user.email}")
            return new_user
        else:
            logger.error(f"Failed to create user: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
    except Exception as e:
        logger.error(f"Error creating user {user.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """Endpoint for initial login (returns JWT token if credentials are valid)"""
    logger.info(f"Login attempt for user: {form_data.username}")
    
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.warning(f"Authentication failed for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    logger.info(f"Access token generated for user: {user.email}")
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register", response_model=Token)
async def register_new_user(user: UserCreate):
    """Endpoint for user registration"""
    logger.info(f"Registration request for user: {user.email}")
    
    # Create the user
    db_user = await create_user(user)
    
    # Generate access token for the new user
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=access_token_expires
    )
    
    logger.info(f"User registered successfully: {user.email}")
    return {"access_token": access_token, "token_type": "bearer"}

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

@router.post("/generate-otp")
async def generate_otp(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Endpoint to generate OTP for MFA"""
    try:
        token = credentials.credentials
        email = decode_token(token).get("sub")  # Your existing decode logic
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        logger.info(f"Generating OTP for user: {email}")
        otp = otp_manager.generate_otp(email)
        
        logger.info(f"OTP for {email}: {otp} (Enter this in the frontend)")
        return {"message": "OTP generated and logged (check backend console)"}
        
    except Exception as e:
        logger.error(f"Error in generate-otp: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error generating OTP"
        )
    
@router.post("/verify-mfa", response_model=Token)
async def verify_mfa(
    verification: OTPVerification,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Endpoint to verify MFA OTP"""
    try:
        token = credentials.credentials
        decoded_token = decode_token(token)
        email = decoded_token.get("sub")
        
        if not email or email != verification.email:
            logger.warning(f"Token/email mismatch. Token email: {email}, Request email: {verification.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token or email mismatch"
            )
        
        logger.info(f"MFA verification attempt for {email}")
        
        if not otp_manager.verify_otp(email, verification.mfa_code):
            logger.warning(f"Invalid OTP for {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP code"
            )
        
        # Generate new token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": email, "mfa_verified": True},
            expires_delta=access_token_expires
        )
        
        logger.info(f"MFA verified for {email}")
        return {"access_token": access_token, "token_type": "bearer"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid request format"
        )