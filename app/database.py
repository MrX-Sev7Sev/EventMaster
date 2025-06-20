from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "postgresql://mrx:2IAsjs5oOfdEgB2pacpqdPZbhaMOmFN1@dpg-d1aj6jmmcj7s73fjkdu0-a.oregon-postgres.render.com/urfutable"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
