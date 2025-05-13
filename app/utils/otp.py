import pyotp
import base64
import os
from dotenv import load_dotenv
from ..utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

class OTPManager:
    def __init__(self):
        self.otp_expiry_seconds = 300  # 5 minutes
        self.current_otps = {}
        
        # Ensure we have a valid key
        raw_key = os.getenv("ENCRYPTION_KEY")
        if not raw_key or len(raw_key) < 16:  # Minimum 16 chars for safety
            logger.error("Invalid ENCRYPTION_KEY - must be at least 16 characters")
            raise ValueError("Invalid encryption key configuration")
            
        # Create a base32 encoded key of proper length
        self.base32_key = base64.b32encode(raw_key.encode()[:32]).decode()

    def generate_otp(self, email: str) -> str:
        """Generate a time-based OTP for the given email"""
        try:
            # Create unique key per user by combining with email
            user_key = f"{self.base32_key}{email}"[:32]
            totp = pyotp.TOTP(user_key, interval=self.otp_expiry_seconds)
            otp = totp.now()
            
            # For development, store the OTP
            self.current_otps[email] = otp
            logger.info(f"Generated OTP for {email}")
            logger.debug(f"DEBUG OTP for {email}: {otp}")
            
            return otp
        except Exception as e:
            logger.error(f"OTP generation failed for {email}: {str(e)}")
            raise

    def verify_otp(self, email: str, otp: str) -> bool:
        """Verify the OTP for the given email"""
        try:
            # For development, check against stored OTPs
            if email in self.current_otps:
                is_valid = self.current_otps[email] == otp
                if is_valid:
                    del self.current_otps[email]
                return is_valid
                
            # Fallback to proper TOTP verification
            user_key = f"{self.base32_key}{email}"[:32]
            totp = pyotp.TOTP(user_key, interval=self.otp_expiry_seconds)
            return totp.verify(otp)
        except Exception as e:
            logger.error(f"OTP verification failed for {email}: {str(e)}")
            return False