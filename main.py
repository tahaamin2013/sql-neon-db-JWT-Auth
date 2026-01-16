# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import timedelta
from pydantic import BaseModel
from auth import create_access_token, decode_token
from config import get_settings
from models import User, Task, TaskCreate
from database import get_session, create_db_and_tables
from security import hash_password, verify_password

# Initialize FastAPI application
app = FastAPI()
settings = get_settings()

# OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Lifespan event: runs on application startup
@app.on_event("startup")
def on_startup():
    """Initialize database tables on app startup"""
    create_db_and_tables()

# ==================== SIGNUP ====================
class SignupData(BaseModel):
    """Request model for user registration"""
    email: str
    password: str

@app.post("/signup", status_code=201)
def signup(signup_data: SignupData, session: Session = Depends(get_session)):
    """Create a new user account"""
    # Check if user already exists
    existing_user = session.exec(select(User).where(User.email == signup_data.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create new user with hashed password
    user = User(
        email=signup_data.email,
        hashed_password=hash_password(signup_data.password)
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"id": user.id, "email": user.email}

# ==================== LOGIN ====================
@app.post("/token")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    """Authenticate user and return JWT access token"""
    # Find user by email (username field)
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    
    # Verify credentials
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate JWT token
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ==================== CURRENT USER ====================
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
) -> User:
    """Extract and validate user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Decode JWT token
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    
    # Extract email from token
    email: str = payload.get("sub")
    if email is None:
        raise credentials_exception
    
    # Find user in database
    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/users/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info"""
    return {"id": current_user.id, "email": current_user.email}

# ==================== TASK ENDPOINTS ====================
@app.post("/tasks", status_code=201)
def create_task(
    task: TaskCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """Create a new task for current user"""
    db_task = Task(**task.model_dump(), owner_id=current_user.id)
    session.add(db_task)
    session.commit()
    session.refresh(db_task)
    return db_task

@app.get("/tasks")
def list_tasks(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """List all tasks for current user"""
    return session.exec(select(Task).where(Task.owner_id == current_user.id)).all()
