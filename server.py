from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'market-royal-secret-key-2024')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app
app = FastAPI(title="Market Royal API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# ============== MODELS ==============

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(UserBase):
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    role: str
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ProductBase(BaseModel):
    name: str
    name_en: Optional[str] = None
    description: str
    description_en: Optional[str] = None
    category: str
    image_url: str
    amazon_link: str
    price: Optional[str] = None

class ProductCreate(ProductBase):
    pass

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    name_en: Optional[str] = None
    description: Optional[str] = None
    description_en: Optional[str] = None
    category: Optional[str] = None
    image_url: Optional[str] = None
    amazon_link: Optional[str] = None
    price: Optional[str] = None

class ProductResponse(ProductBase):
    model_config = ConfigDict(extra="ignore")
    id: str
    click_count: int = 0
    created_at: str

class ClickEvent(BaseModel):
    product_id: str
    referrer: Optional[str] = None

class ClickResponse(BaseModel):
    success: bool
    message: str

class CategoryResponse(BaseModel):
    id: str
    name: str
    name_en: str
    slug: str
    icon: str

class AnalyticsResponse(BaseModel):
    total_products: int
    total_clicks: int
    clicks_today: int
    clicks_this_week: int
    clicks_this_month: int
    top_products: List[dict]
    clicks_by_category: List[dict]
    clicks_over_time: List[dict]

# ============== HELPER FUNCTIONS ==============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# ============== CATEGORIES ==============

CATEGORIES = [
    {"id": "casa", "name": "Casa", "name_en": "Home", "slug": "casa", "icon": "Home"},
    {"id": "tecnologia", "name": "Tecnologia", "name_en": "Technology", "slug": "tecnologia", "icon": "Smartphone"},
    {"id": "sport", "name": "Sport", "name_en": "Sports", "slug": "sport", "icon": "Dumbbell"},
    {"id": "benessere", "name": "Benessere", "name_en": "Wellness", "slug": "benessere", "icon": "Heart"},
    {"id": "accessori", "name": "Accessori", "name_en": "Accessories", "slug": "accessori", "icon": "Watch"},
]

# ============== AUTH ROUTES ==============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if this is the first user (make them admin)
    user_count = await db.users.count_documents({})
    role = "admin" if user_count == 0 else "user"
    
    user_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "role": role,
        "created_at": created_at
    }
    
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id, user_data.email, role)
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            role=role,
            created_at=created_at
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["email"], user["role"])
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            role=user["role"],
            created_at=user["created_at"]
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(
        id=user["id"],
        email=user["email"],
        role=user["role"],
        created_at=user["created_at"]
    )

# ============== CATEGORY ROUTES ==============

@api_router.get("/categories", response_model=List[CategoryResponse])
async def get_categories():
    return CATEGORIES

# ============== PRODUCT ROUTES (PUBLIC) ==============

@api_router.get("/products/public", response_model=List[ProductResponse])
async def get_public_products(category: Optional[str] = None):
    query = {}
    if category:
        query["category"] = category
    
    products = await db.products.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return products

@api_router.get("/products/public/{product_id}", response_model=ProductResponse)
async def get_public_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

# ============== PRODUCT ROUTES (ADMIN) ==============

@api_router.get("/products", response_model=List[ProductResponse])
async def get_products(current_user: dict = Depends(get_admin_user)):
    products = await db.products.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return products

@api_router.post("/products", response_model=ProductResponse)
async def create_product(product: ProductCreate, current_user: dict = Depends(get_admin_user)):
    product_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    
    product_doc = {
        "id": product_id,
        **product.model_dump(),
        "click_count": 0,
        "created_at": created_at
    }
    
    await db.products.insert_one(product_doc)
    
    # Remove _id before returning
    product_doc.pop("_id", None)
    return product_doc

@api_router.put("/products/{product_id}", response_model=ProductResponse)
async def update_product(product_id: str, product: ProductUpdate, current_user: dict = Depends(get_admin_user)):
    existing = await db.products.find_one({"id": product_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = {k: v for k, v in product.model_dump().items() if v is not None}
    
    if update_data:
        await db.products.update_one({"id": product_id}, {"$set": update_data})
    
    updated = await db.products.find_one({"id": product_id}, {"_id": 0})
    return updated

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, current_user: dict = Depends(get_admin_user)):
    result = await db.products.delete_one({"id": product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Also delete related clicks
    await db.clicks.delete_many({"product_id": product_id})
    
    return {"success": True, "message": "Product deleted"}

# ============== CLICK TRACKING ==============

@api_router.post("/clicks", response_model=ClickResponse)
async def track_click(click: ClickEvent):
    # Verify product exists
    product = await db.products.find_one({"id": click.product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Record click
    click_doc = {
        "id": str(uuid.uuid4()),
        "product_id": click.product_id,
        "category": product.get("category", ""),
        "referrer": click.referrer,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    await db.clicks.insert_one(click_doc)
    
    # Update product click count
    await db.products.update_one(
        {"id": click.product_id},
        {"$inc": {"click_count": 1}}
    )
    
    return ClickResponse(success=True, message="Click tracked")

# ============== ANALYTICS (ADMIN) ==============

@api_router.get("/analytics", response_model=AnalyticsResponse)
async def get_analytics(current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())
    month_start = today_start.replace(day=1)
    
    # Total counts
    total_products = await db.products.count_documents({})
    total_clicks = await db.clicks.count_documents({})
    
    # Clicks today
    clicks_today = await db.clicks.count_documents({
        "timestamp": {"$gte": today_start.isoformat()}
    })
    
    # Clicks this week
    clicks_this_week = await db.clicks.count_documents({
        "timestamp": {"$gte": week_start.isoformat()}
    })
    
    # Clicks this month
    clicks_this_month = await db.clicks.count_documents({
        "timestamp": {"$gte": month_start.isoformat()}
    })
    
    # Top products by clicks
    top_products = await db.products.find(
        {}, {"_id": 0, "id": 1, "name": 1, "click_count": 1, "category": 1}
    ).sort("click_count", -1).limit(10).to_list(10)
    
    # Clicks by category
    pipeline = [
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    clicks_by_category_cursor = db.clicks.aggregate(pipeline)
    clicks_by_category = [{"category": doc["_id"], "count": doc["count"]} async for doc in clicks_by_category_cursor]
    
    # Clicks over time (last 30 days)
    thirty_days_ago = today_start - timedelta(days=30)
    time_pipeline = [
        {"$match": {"timestamp": {"$gte": thirty_days_ago.isoformat()}}},
        {"$addFields": {"date": {"$substr": ["$timestamp", 0, 10]}}},
        {"$group": {"_id": "$date", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]
    clicks_over_time_cursor = db.clicks.aggregate(time_pipeline)
    clicks_over_time = [{"date": doc["_id"], "count": doc["count"]} async for doc in clicks_over_time_cursor]
    
    return AnalyticsResponse(
        total_products=total_products,
        total_clicks=total_clicks,
        clicks_today=clicks_today,
        clicks_this_week=clicks_this_week,
        clicks_this_month=clicks_this_month,
        top_products=top_products,
        clicks_by_category=clicks_by_category,
        clicks_over_time=clicks_over_time
    )

# ============== HEALTH CHECK ==============

@api_router.get("/")
async def root():
    return {"message": "Market Royal API", "status": "healthy"}

@api_router.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
