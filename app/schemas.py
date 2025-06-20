from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    email: EmailStr
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_active: bool
    
    class Config:
        orm_mode = True

class GameBase(BaseModel):
    title: str
    description: str | None = None

class GameCreate(GameBase):
    pass

class Game(GameBase):
    id: int
    owner_id: int
    
    class Config:
        orm_mode = True
