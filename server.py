
from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Any
import uuid
from datetime import datetime, timezone, date
import jwt
import bcrypt
import pandas as pd
from io import BytesIO, StringIO
import csv

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'call_center_db')]

# JWT Configuration - Removed hardcoded default secret for security
JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set. Application cannot start.")
JWT_ALGORITHM = "HS256"

app = FastAPI(title="Call Center Dashboard API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============ MODELS ============

class UserCreate(BaseModel):
    username: str
    password: str
    name: str
    role: str = "agent"

class UserLogin(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    """Validation model for user updates"""
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

    class Config:
        extra = "forbid"

class UserResponse(BaseModel):
    id: str
    username: str
    name: str
    role: str
    is_active: bool

# ... (Other models for CallLogs and Reasons omitted for brevity, keeping existing logic)

# ============ AUTH HELPERS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc).timestamp() + 86400
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if not user or not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# ============ ROUTES ============

@api_router.post("/auth/login")
async def login(user: UserLogin):
    db_user = await db.users.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(db_user["id"], db_user["username"], db_user["role"])
    return {"token": token, "user": {"id": db_user["id"], "role": db_user["role"], "name": db_user["name"]}}

@api_router.put("/users/{user_id}")
async def update_user(user_id: str, updates: UserUpdate, admin: dict = Depends(get_admin_user)):
    """Updated with Pydantic validation for data integrity"""
    update_data = updates.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid update fields provided")
    
    if "password" in update_data:
        update_data["password"] = hash_password(update_data["password"])
    
    result = await db.users.update_one({"id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User updated successfully"}

@api_router.post("/upload")
async def upload_file(file: UploadFile = File(...), admin: dict = Depends(get_admin_user)):
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="Only Excel files are supported")
    
    try:
        contents = await file.read()
        xlsx = pd.ExcelFile(BytesIO(contents))
        if 'Export' not in xlsx.sheet_names:
            raise HTTPException(status_code=400, detail="Export sheet missing")
        
        df = pd.read_excel(xlsx, sheet_name='Export')
        records_processed = 0
        
        for _, row in df.iterrows():
            try:
                # Sanitize Record ID
                raw_id = row.get('id')
                if pd.isna(raw_id): continue
                record_id = str(int(float(raw_id)))
                
                # Logic for status and dates (Fixing Timezone Naive error)
                approved_date_raw = row.get('Approved date')
                ageing = None
                if pd.notna(approved_date_raw):
                    dt_approved = pd.to_datetime(approved_date_raw).to_pydatetime()
                    if dt_approved.tzinfo is None:
                        dt_approved = dt_approved.replace(tzinfo=timezone.utc)
                    
                    # Correct timezone-aware ageing calculation
                    ageing = (datetime.now(timezone.utc) - dt_approved).days

                record_doc = {
                    "record_id": record_id,
                    "quotes_last_status": str(row.get('Quotes_last_status', 'New')),
                    "ageing": ageing,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
                
                await db.records.update_one(
                    {"record_id": record_id}, 
                    {"$set": record_doc}, 
                    upsert=True
                )
                records_processed += 1
            except Exception as e:
                logger.error(f"Error processing row for ID {raw_id}: {e}")
                continue

        return {"message": "Upload complete", "processed": records_processed}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/reports/summary")
async def get_reports_summary(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    vip_filter: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Refactored to use MongoDB Aggregation for performance"""
    match_query = {}
    if start_date or end_date:
        date_query = {}
        if start_date: date_query["$gte"] = start_date
        if end_date: date_query["$lte"] = end_date + "T23:59:59"
        match_query["submit_date"] = date_query

    if vip_filter:
        match_query["vip_status"] = "VIP" if vip_filter.upper() == "VIP" else {"$ne": "VIP"}

    pipeline = [
        {"$match": match_query},
        {"$facet": {
            "totals": [
                {"$group": {
                    "_id": None,
                    "total_records": {"$sum": 1},
                    "unique_users": {"$addToSet": "$user_id"},
                    "approved": {"$sum": {"$cond": [{"$eq": ["$quotes_last_status", "Approved"]}, 1, 0]}},
                    "pending": {"$sum": {"$cond": [{"$eq": ["$quotes_last_status", "New"]}, 1, 0]}},
                }},
                {"$project": {
                    "total_records": 1, 
                    "unique_user_ids": {"$size": "$unique_users"},
                    "approved": 1, "pending": 1
                }}
            ],
            "countries": [{"$group": {"_id": "$country", "count": {"$sum": 1}}}]
        }}
    ]
    
    result = await db.records.aggregate(pipeline).to_list(1)
    data = result[0] if result else {}
    stats = data.get("totals", [{}])[0]
    
    return {
        "total_records": stats.get("total_records", 0),
        "unique_user_ids": stats.get("unique_user_ids", 0),
        "status_breakdown": {
            "approved": stats.get("approved", 0),
            "pending": stats.get("pending", 0)
        },
        "country_breakdown": {c["_id"] or "Unknown": c["count"] for c in data.get("countries", [])}
    }

# ... (Include other necessary routes from original server.py)

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


