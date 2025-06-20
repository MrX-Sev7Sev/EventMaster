from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional

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

class User(UserBase):
    id: int
    is_active: bool = True
    avatar: Optional[str] = None
    
    class Config:
        orm_mode = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "email": "user@example.com",
                "username": "john_doe",
                "is_active": True,
                "avatar": "https://example.com/avatar.jpg"
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
    created_at: str
    
    class Config:
        orm_mode = True
