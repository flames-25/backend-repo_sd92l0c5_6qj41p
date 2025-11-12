"""
Application Database Schemas

Each Pydantic model below maps to a MongoDB collection whose name is the lowercase class name.
- User -> "user"
- Project -> "project"
- Task -> "task"
- Subtask -> "subtask"
- Session -> "session" (time tracking sessions)

These schemas are used for validation at API boundaries. Additional computed fields
(like _id, timestamps) are injected by database helpers.
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hashed password")
    theme: Literal["light", "dark"] = Field("light", description="Preferred theme")
    telemetry_opt_in: bool = Field(False, description="User opted-in to telemetry")


class Project(BaseModel):
    owner_id: str = Field(..., description="User _id string")
    name: str = Field(..., description="Project name")
    description: Optional[str] = Field(None, description="Project description")
    color: Optional[str] = Field(None, description="Hex color for UI")


Priority = Literal["low", "medium", "high", "urgent"]


class Task(BaseModel):
    project_id: str = Field(..., description="Project _id string")
    owner_id: str = Field(..., description="User _id string")
    title: str = Field(...)
    description: Optional[str] = None
    priority: Priority = Field("medium")
    due_date: Optional[datetime] = Field(None)
    estimated_minutes: Optional[int] = Field(None, ge=0)
    scheduled_date: Optional[datetime] = Field(None)
    completed: bool = Field(False)


class Subtask(BaseModel):
    task_id: str = Field(..., description="Task _id string")
    owner_id: str = Field(..., description="User _id string")
    title: str
    order: int = Field(0, ge=0)
    completed: bool = Field(False)


class Session(BaseModel):
    owner_id: str = Field(..., description="User _id string")
    task_id: Optional[str] = Field(None, description="Optional task _id if focused on a task")
    mode: Literal["pomodoro", "stopwatch"] = Field("pomodoro")
    started_at: datetime = Field(...)
    ended_at: Optional[datetime] = Field(None)
    duration_seconds: Optional[int] = Field(None, ge=0)
    note: Optional[str] = Field(None)
    pomodoro_length: Optional[int] = Field(None, description="minutes")
    short_break: Optional[int] = Field(None, description="minutes")
    long_break: Optional[int] = Field(None, description="minutes")
