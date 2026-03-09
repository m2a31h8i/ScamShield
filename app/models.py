from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    role = Column(String, default="user")
    risk_score = Column(Float, default=0.0)

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    tool = Column(String)
    target = Column(String)
    result = Column(Text)
    risk_level = Column(String)  # low / medium / high
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")

class PlatformAlert(Base):
    __tablename__ = "platform_alerts"

    id = Column(Integer, primary_key=True)
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class WeeklyReport(Base):
    __tablename__ = "weekly_reports"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)  # null = admin report
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)