import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents

# App and CORS
app = FastAPI(title="Blitzit-Inspired Productivity API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth and Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

# Simple in-memory rate limiting bucket per IP
_rate_bucket: Dict[str, List[float]] = {}
RATE_LIMIT_PER_MIN = 120


async def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = datetime.now().timestamp()
    window_start = now - 60
    bucket = _rate_bucket.get(ip, [])
    bucket = [t for t in bucket if t > window_start]
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)
    _rate_bucket[ip] = bucket


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=8)


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class ProjectBody(BaseModel):
    name: str
    description: Optional[str] = None
    color: Optional[str] = None


class TaskBody(BaseModel):
    project_id: str
    title: str
    description: Optional[str] = None
    priority: str = Field("medium")
    due_date: Optional[datetime] = None
    estimated_minutes: Optional[int] = None
    scheduled_date: Optional[datetime] = None
    completed: bool = False


class SubtaskBody(BaseModel):
    task_id: str
    title: str
    order: int = 0
    completed: bool = False


class SessionStartBody(BaseModel):
    task_id: Optional[str] = None
    mode: str = Field("pomodoro")
    pomodoro_length: Optional[int] = 25
    short_break: Optional[int] = 5
    long_break: Optional[int] = 15


class SessionStopBody(BaseModel):
    note: Optional[str] = None


# Dependency to get current user from JWT
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> Dict[str, Any]:
    payload = decode_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db["user"].find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.middleware("http")
async def apply_rate_limit(request: Request, call_next):
    try:
        await rate_limit(request)
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    response = await call_next(request)
    return response


@app.get("/")
def root():
    return {"message": "Blitzit-Inspired Productivity API", "version": app.version}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            collections = db.list_collection_names()
            response["collections"] = collections
            response["connection_status"] = "Connected"
        else:
            response["database"] = "⚠️ Not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth routes
@app.post("/auth/register")
def register(body: RegisterBody):
    existing = db["user"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": body.name,
        "email": body.email,
        "password_hash": hash_password(body.password),
        "theme": "light",
        "telemetry_opt_in": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(user_doc)
    uid = str(result.inserted_id)
    # store _id as string for simplicity
    db["user"].update_one({"_id": result.inserted_id}, {"$set": {"_id": uid}})
    token = create_access_token({"sub": uid})
    return {"token": token, "user": {"id": uid, "name": body.name, "email": body.email}}


@app.post("/auth/login")
def login(body: LoginBody):
    user = db["user"].find_one({"email": body.email})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["_id"]})
    return {"token": token, "user": {"id": user["_id"], "name": user.get("name"), "email": user.get("email")}}


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"id": user["_id"], "name": user.get("name"), "email": user.get("email"), "theme": user.get("theme", "light")}


# Projects CRUD
@app.get("/projects")
def list_projects(user=Depends(get_current_user)):
    docs = list(db["project"].find({"owner_id": user["_id"]}))
    for d in docs:
        d["id"] = d.pop("_id")
    return docs


@app.post("/projects")
def create_project(body: ProjectBody, user=Depends(get_current_user)):
    doc = {
        "owner_id": user["_id"],
        "name": body.name,
        "description": body.description,
        "color": body.color,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["project"].insert_one(doc)
    pid = str(res.inserted_id)
    db["project"].update_one({"_id": res.inserted_id}, {"$set": {"_id": pid}})
    doc["_id"] = pid
    doc["id"] = pid
    return doc


@app.put("/projects/{project_id}")
def update_project(project_id: str, body: ProjectBody, user=Depends(get_current_user)):
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    upd["updated_at"] = datetime.now(timezone.utc)
    result = db["project"].update_one({"_id": project_id, "owner_id": user["_id"]}, {"$set": upd})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    d = db["project"].find_one({"_id": project_id})
    d["id"] = d.pop("_id")
    return d


@app.delete("/projects/{project_id}")
def delete_project(project_id: str, user=Depends(get_current_user)):
    db["task"].delete_many({"project_id": project_id, "owner_id": user["_id"]})
    result = db["project"].delete_one({"_id": project_id, "owner_id": user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"ok": True}


# Tasks CRUD
@app.get("/tasks")
def list_tasks(project_id: Optional[str] = None, user=Depends(get_current_user)):
    query = {"owner_id": user["_id"]}
    if project_id:
        query["project_id"] = project_id
    docs = list(db["task"].find(query))
    for d in docs:
        d["id"] = d.pop("_id")
    return docs


@app.post("/tasks")
def create_task(body: TaskBody, user=Depends(get_current_user)):
    doc = {
        **body.model_dump(),
        "owner_id": user["_id"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["task"].insert_one(doc)
    tid = str(res.inserted_id)
    db["task"].update_one({"_id": res.inserted_id}, {"$set": {"_id": tid}})
    doc["_id"] = tid
    doc["id"] = tid
    return doc


@app.put("/tasks/{task_id}")
def update_task(task_id: str, body: TaskBody, user=Depends(get_current_user)):
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    upd["updated_at"] = datetime.now(timezone.utc)
    result = db["task"].update_one({"_id": task_id, "owner_id": user["_id"]}, {"$set": upd})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    d = db["task"].find_one({"_id": task_id})
    d["id"] = d.pop("_id")
    return d


@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, user=Depends(get_current_user)):
    db["subtask"].delete_many({"task_id": task_id, "owner_id": user["_id"]})
    result = db["task"].delete_one({"_id": task_id, "owner_id": user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"ok": True}


# Subtasks
@app.get("/tasks/{task_id}/subtasks")
def list_subtasks(task_id: str, user=Depends(get_current_user)):
    docs = list(db["subtask"].find({"task_id": task_id, "owner_id": user["_id"]}).sort("order"))
    for d in docs:
        d["id"] = d.pop("_id")
    return docs


@app.post("/tasks/{task_id}/subtasks")
def create_subtask(task_id: str, body: SubtaskBody, user=Depends(get_current_user)):
    doc = {
        "task_id": task_id,
        "owner_id": user["_id"],
        "title": body.title,
        "order": body.order,
        "completed": body.completed,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["subtask"].insert_one(doc)
    sid = str(res.inserted_id)
    db["subtask"].update_one({"_id": res.inserted_id}, {"$set": {"_id": sid}})
    doc["_id"] = sid
    doc["id"] = sid
    return doc


@app.put("/subtasks/{subtask_id}")
def update_subtask(subtask_id: str, body: SubtaskBody, user=Depends(get_current_user)):
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    upd["updated_at"] = datetime.now(timezone.utc)
    result = db["subtask"].update_one({"_id": subtask_id, "owner_id": user["_id"]}, {"$set": upd})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Subtask not found")
    d = db["subtask"].find_one({"_id": subtask_id})
    d["id"] = d.pop("_id")
    return d


@app.delete("/subtasks/{subtask_id}")
def delete_subtask(subtask_id: str, user=Depends(get_current_user)):
    result = db["subtask"].delete_one({"_id": subtask_id, "owner_id": user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Subtask not found")
    return {"ok": True}


# Time tracking sessions
@app.post("/sessions/start")
def start_session(body: SessionStartBody, user=Depends(get_current_user)):
    doc = {
        "owner_id": user["_id"],
        "task_id": body.task_id,
        "mode": body.mode,
        "started_at": datetime.now(timezone.utc),
        "ended_at": None,
        "duration_seconds": None,
        "pomodoro_length": body.pomodoro_length,
        "short_break": body.short_break,
        "long_break": body.long_break,
    }
    res = db["session"].insert_one(doc)
    sid = str(res.inserted_id)
    db["session"].update_one({"_id": res.inserted_id}, {"$set": {"_id": sid}})
    return {"id": sid, **doc}


@app.post("/sessions/{session_id}/stop")
def stop_session(session_id: str, body: SessionStopBody, user=Depends(get_current_user)):
    sess = db["session"].find_one({"_id": session_id, "owner_id": user["_id"]})
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("ended_at"):
        return {"id": session_id, **sess}
    ended = datetime.now(timezone.utc)
    duration = int((ended - sess["started_at"]).total_seconds())
    db["session"].update_one({"_id": session_id}, {"$set": {"ended_at": ended, "duration_seconds": duration, "note": body.note}})
    sess = db["session"].find_one({"_id": session_id})
    sess["id"] = sess.pop("_id")
    return sess


@app.get("/reports/summary")
def reports_summary(range: str = "daily", user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    if range == "weekly":
        start = now - timedelta(days=7)
    else:
        start = now - timedelta(days=1)
    sessions = list(db["session"].find({"owner_id": user["_id"], "started_at": {"$gte": start}}))
    total = sum((s.get("duration_seconds") or 0) for s in sessions)
    by_project: Dict[str, int] = {}
    for s in sessions:
        if s.get("task_id"):
            t = db["task"].find_one({"_id": s["task_id"]})
            if t:
                pid = t.get("project_id", "unknown")
                by_project[pid] = by_project.get(pid, 0) + (s.get("duration_seconds") or 0)
    return {"total_seconds": total, "by_project": by_project, "range": range}


@app.get("/export/csv")
def export_csv(user=Depends(get_current_user)):
    import csv
    from io import StringIO
    sessions = list(db["session"].find({"owner_id": user["_id"]}))
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["session_id", "task_id", "mode", "started_at", "ended_at", "duration_seconds"])
    for s in sessions:
        writer.writerow([s.get("_id"), s.get("task_id"), s.get("mode"), s.get("started_at"), s.get("ended_at"), s.get("duration_seconds")])
    return {"filename": "sessions.csv", "content": output.getvalue()}


@app.get("/export/task/{task_id}/markdown")
def export_task_markdown(task_id: str, user=Depends(get_current_user)):
    task = db["task"].find_one({"_id": task_id, "owner_id": user["_id"]})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    subs = list(db["subtask"].find({"task_id": task_id, "owner_id": user["_id"]}).sort("order"))
    md = [f"# {task.get('title')}", "", task.get("description", ""), "", "## Subtasks"]
    for s in subs:
        md.append(f"- [{'x' if s.get('completed') else ' '}] {s.get('title')}")
    return {"filename": f"task-{task_id}.md", "content": "\n".join(md)}


# Settings
class SettingsBody(BaseModel):
    theme: Optional[str] = None
    telemetry_opt_in: Optional[bool] = None


@app.patch("/settings")
def update_settings(body: SettingsBody, user=Depends(get_current_user)):
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    if not upd:
        return {"ok": True}
    db["user"].update_one({"_id": user["_id"]}, {"$set": upd})
    u = db["user"].find_one({"_id": user["_id"]})
    return {"id": u["_id"], "theme": u.get("theme", "light"), "telemetry_opt_in": u.get("telemetry_opt_in", False)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
