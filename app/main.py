from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth, passwords  # Add passwords import
from .utils.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Password Manager API",
    description="API for managing secure passwords",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(passwords.router)  # Add this line

@app.on_event("startup")
async def startup_db_client():
    logger.info("Starting up Password Manager API")

@app.on_event("shutdown")
async def shutdown_db_client():
    logger.info("Shutting down Password Manager API")

@app.get("/")
async def root():
    return {"message": "Password Manager API is running"}