from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime
from app.schemas import UserSchema as User

class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

class UserSchema(BaseModel):
    id: int
    is_active: bool = True
    avatar: Optional[str] = None
    created_at: datetime  # Добавлено!

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "email": "user@example.com",
                "username": "john_doe",
                "is_active": True,
                "avatar": "https://example.com/avatar.jpg",
                "created_at": "2024-01-01T00:00:00"
            }
        }

class GameBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

class GameCreate(GameBase):
    pass

class Game(GameBase):
    id: int
    owner_id: int
    created_at: datetime  # Исправлено с str на datetime (если нужно)
    
    class Config:
        from_attributes = True
