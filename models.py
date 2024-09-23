from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from datetime import UTC, datetime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    analyses = relationship("Analysis", back_populates="user")

class Analysis(Base):
  __tablename__ = "analyses"

  id = Column(Integer, primary_key=True, index=True)
  user_id = Column(Integer, ForeignKey("users.id"), index=True)
  guest_session_id = Column(String, index=True)
  user_type = Column(String)
  text = Column(Text)
  created_at = Column(DateTime, default=datetime.now(UTC))
  user = relationship("User", back_populates="analyses")
  results = relationship("Result", back_populates="analysis")

class Result(Base):
  __tablename__ = "results"

  id = Column(Integer, primary_key=True, index=True)
  analysis_id = Column(Integer, ForeignKey("analyses.id"))
  analyzer = Column(String)
  sentiment = Column(String)
  score = Column(Float)
  additional_data = Column(JSONB)
  created_at = Column(DateTime, default=datetime.now(UTC))
  analysis = relationship("Analysis", back_populates="results")