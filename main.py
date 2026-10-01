
import os
from pathlib import Path

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_
from contextlib import asynccontextmanager
import threading





# --- DB & Socket Server Merge ---
import hashlib
import hmac
import secrets
import sqlite3
import socket
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker

import hashlib
import hmac
import secrets
import sqlite3

from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./hospital.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def hash_password(password: str) -> str:
    """Securely hash a password using PBKDF2-HMAC-SHA256 with a unique random salt."""
    if not password:
        return ""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return f"pbkdf2_sha256${salt}${dk}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify password against stored hash, supporting backward compatibility with plain text."""
    if not stored_hash or not plain_password:
        return False
    if stored_hash.startswith("pbkdf2_sha256$"):
        try:
            parts = stored_hash.split("$")
            if len(parts) == 3:
                salt = parts[1]
                expected_dk = parts[2]
                computed = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
                return hmac.compare_digest(expected_dk, computed)
        except Exception:
            return False
    # Backward compatibility for existing plaintext demo passwords
    return plain_password == stored_hash


def ensure_database_schema():
    conn = sqlite3.connect("hospital.db")
    try:
        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if not user_cols:
            conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, name TEXT, email TEXT, role TEXT NOT NULL, must_change_password INTEGER DEFAULT 0, status TEXT DEFAULT 'Active')")
            user_cols = {"username", "password", "name", "email", "role", "must_change_password", "status"}
        for col_name, col_def in {
            "name": "TEXT",
            "email": "TEXT",
            "role": "TEXT",
            "must_change_password": "INTEGER DEFAULT 0",
            "status": "TEXT DEFAULT 'Active'"
        }.items():
            if col_name not in user_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

        patient_cols = {row[1] for row in conn.execute("PRAGMA table_info(patients)").fetchall()}
        if not patient_cols:
            conn.execute("CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, gender TEXT, phone TEXT, disease TEXT, address TEXT, hospital_name TEXT, ward TEXT, status TEXT, user_id INTEGER, doctor_id INTEGER, nurse_id INTEGER)")
            patient_cols = {"name", "age", "gender", "phone", "disease", "address", "hospital_name", "ward", "status", "user_id", "doctor_id", "nurse_id"}
        for col_name, col_def in {
            "ward": "TEXT",
            "status": "TEXT DEFAULT 'Active'",
            "address": "TEXT DEFAULT 'Not Specified'",
            "hospital_name": "TEXT DEFAULT 'Smart Hospital Central'",
            "user_id": "INTEGER",
            "doctor_id": "INTEGER",
            "nurse_id": "INTEGER"
        }.items():
            if col_name not in patient_cols:
                conn.execute(f"ALTER TABLE patients ADD COLUMN {col_name} {col_def}")

        doctor_cols = {row[1] for row in conn.execute("PRAGMA table_info(doctors)").fetchall()}
        if not doctor_cols:
            conn.execute("CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, address TEXT, hospital_name TEXT, specialization TEXT, department TEXT, phone TEXT, shift TEXT, status TEXT, user_id INTEGER)")
            doctor_cols = {"name", "age", "address", "hospital_name", "specialization", "department", "phone", "shift", "status", "user_id"}
        for col_name, col_def in {
            "age": "INTEGER",
            "address": "TEXT DEFAULT 'Not Specified'",
            "hospital_name": "TEXT DEFAULT 'Smart Hospital Central'",
            "department": "TEXT",
            "shift": "TEXT",
            "status": "TEXT DEFAULT 'Active'",
            "user_id": "INTEGER"
        }.items():
            if col_name not in doctor_cols:
                conn.execute(f"ALTER TABLE doctors ADD COLUMN {col_name} {col_def}")

        nurse_cols = {row[1] for row in conn.execute("PRAGMA table_info(nurses)").fetchall()}
        if not nurse_cols:
            conn.execute("CREATE TABLE IF NOT EXISTS nurses (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, address TEXT, hospital_name TEXT, department TEXT, shift TEXT, phone TEXT, status TEXT, user_id INTEGER)")
            nurse_cols = {"name", "age", "address", "hospital_name", "department", "shift", "phone", "status", "user_id"}
        for col_name, col_def in {
            "age": "INTEGER",
            "address": "TEXT DEFAULT 'Not Specified'",
            "hospital_name": "TEXT DEFAULT 'Smart Hospital Central'",
            "shift": "TEXT",
            "status": "TEXT DEFAULT 'Active'",
            "user_id": "INTEGER"
        }.items():
            if col_name not in nurse_cols:
                conn.execute(f"ALTER TABLE nurses ADD COLUMN {col_name} {col_def}")

        appt_cols = {row[1] for row in conn.execute("PRAGMA table_info(appointments)").fetchall()}
        if appt_cols:
            for col_name, col_def in {
                "reason": "TEXT",
                "doctor_id": "INTEGER",
                "patient_id": "INTEGER"
            }.items():
                if col_name not in appt_cols:
                    conn.execute(f"ALTER TABLE appointments ADD COLUMN {col_name} {col_def}")

        message_cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if not message_cols:
            conn.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, patient_id INTEGER, message_type TEXT, message TEXT, date TEXT, time TEXT, status TEXT DEFAULT 'Unread')")

        conn.commit()
    finally:
        conn.close()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=True)
    role = Column(String, nullable=False)
    must_change_password = Column(Integer, default=0)
    status = Column(String, default="Active")


class Patient(Base):
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    age = Column(Integer)
    gender = Column(String)
    phone = Column(String)
    disease = Column(String)
    address = Column(String, default="Not Specified")
    hospital_name = Column(String, default="Smart Hospital Central")
    ward = Column(String, default="General")
    status = Column(String, default="Active")
    user_id = Column(Integer, unique=True, nullable=True)
    doctor_id = Column(Integer, nullable=True)
    nurse_id = Column(Integer, nullable=True)


class Doctor(Base):
    __tablename__ = "doctors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    age = Column(Integer, nullable=True)
    address = Column(String, default="Not Specified")
    hospital_name = Column(String, default="Smart Hospital Central")
    specialization = Column(String)
    department = Column(String, default="General")
    phone = Column(String)
    shift = Column(String, default="Morning")
    status = Column(String, default="Active")
    user_id = Column(Integer, unique=True, nullable=True)


class Nurse(Base):
    __tablename__ = "nurses"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    age = Column(Integer, nullable=True)
    address = Column(String, default="Not Specified")
    hospital_name = Column(String, default="Smart Hospital Central")
    department = Column(String)
    shift = Column(String, default="Morning")
    phone = Column(String)
    status = Column(String, default="Active")
    user_id = Column(Integer, unique=True, nullable=True)


class Appointment(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    patient_name = Column(String)
    doctor_name = Column(String)
    date = Column(String)
    time = Column(String)
    status = Column(String)
    reason = Column(String)
    doctor_id = Column(Integer)
    patient_id = Column(Integer)


class MedicalRecord(Base):
    __tablename__ = "medical_records"

    id = Column(Integer, primary_key=True, index=True)

    patient_id = Column(Integer)
    doctor_id = Column(Integer)
    nurse_id = Column(Integer)

    diagnosis = Column(String)
    advice = Column(Text)
    medicines = Column(Text)
    notes = Column(Text)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer)
    receiver_id = Column(Integer, nullable=True)
    patient_id = Column(Integer, nullable=True)
    message_type = Column(String)
    message = Column(Text)
    date = Column(String)
    time = Column(String)
    status = Column(String, default="Unread")


ensure_database_schema()
Base.metadata.create_all(bind=engine)



# --- Socket Server ---
import socket
import threading

HOST = "0.0.0.0"
PORT = 9000

clients = []


def handle_client(client, address):
    print("Client connected:", address)

    clients.append(client)

    try:
        while True:
            data = client.recv(1024)

            if not data:
                break

            message = data.decode()

            print("Message:", message)

            for other_client in clients:
                if other_client != client:
                    other_client.sendall(message.encode())

    except:
        pass

    finally:
        if client in clients:
            clients.remove(client)

        client.close()

        print("Client disconnected:", address)


def start_socket_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"TCP Socket Server running on port {PORT}")

    while True:
        client, address = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(client, address)
        )

        thread.start()

# --- End Socket Server ---

ROLE_REDIRECTS = {
    "admin": "/admin-dashboard",
    "doctor": "/doctor-dashboard",
    "patient": "/patient-dashboard",
    "nurse": "/nurse-dashboard",
}

DEMO_ACCOUNTS = [
    {
        "username": "admin",
        "password": "admin123",
        "name": "System Administrator",
        "email": "admin@smart-hospital.local",
        "role": "admin",
    },
    {
        "username": "dr_meera",
        "password": "doctor123",
        "name": "Dr. Meera Iyer",
        "email": "meera@smart-hospital.local",
        "role": "doctor",
    },
    {
        "username": "aarav_pat",
        "password": "patient123",
        "name": "Aarav Sharma",
        "email": "aarav@smart-hospital.local",
        "role": "patient",
    },
    {
        "username": "nurse_priya",
        "password": "nurse123",
        "name": "Nurse Priya Sen",
        "email": "priya@smart-hospital.local",
        "role": "nurse",
    },
]


def ensure_demo_accounts(db: Session):
    existing_users = {user.username.lower(): user for user in db.query(User).all()}
    for account in DEMO_ACCOUNTS:
        username = account["username"].lower()
        user = existing_users.get(username)
        if user:
            user.name = account["name"]
            user.email = account["email"]
            user.role = account["role"]
            continue

        db.add(
            User(
                username=account["username"],
                password=account["password"],
                name=account["name"],
                email=account["email"],
                role=account["role"],
                must_change_password=0,
                status="Active",
            )
        )

    db.commit()


def get_current_user(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id:
        return None

    try:
        uid = int(user_id)
    except (ValueError, TypeError):
        return None

    db = SessionLocal()
    user = db.query(User).filter(User.id == uid).first()
    db.close()
    return user


def require_role(request: Request, allowed_roles):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/", status_code=303)
    if getattr(user, "status", "Active") == "Inactive":
        return RedirectResponse("/logout", status_code=303)
    if getattr(user, "must_change_password", 0) == 1 and request.url.path not in ["/change-password", "/logout"]:
        return RedirectResponse("/change-password", status_code=303)
    allowed_roles_lower = [r.lower() for r in allowed_roles]
    if user.role.lower() not in allowed_roles_lower:
        return RedirectResponse("/access-denied", status_code=303)
    return user


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    ensure_demo_accounts(db)

    doctor_user = db.query(User).filter(User.username == "dr_meera").first()
    patient_user = db.query(User).filter(User.username == "aarav_pat").first()
    nurse_user = db.query(User).filter(User.username == "nurse_priya").first()

    doctor = db.query(Doctor).filter(Doctor.user_id == doctor_user.id).first()
    nurse = db.query(Nurse).filter(Nurse.user_id == nurse_user.id).first()
    if not doctor:
        doctor = Doctor(
            name="Dr. Meera Iyer",
            specialization="Cardiology",
            phone="+91 90000 10001",
            user_id=doctor_user.id,
        )
        db.add(doctor)

    if not nurse:
        nurse = Nurse(
            name="Nurse Priya Sen",
            department="ICU",
            phone="+91 90000 20001",
            user_id=nurse_user.id,
        )
        db.add(nurse)

    db.flush()

    patient = db.query(Patient).filter(Patient.user_id == patient_user.id).first()
    if not patient:
        patient = Patient(
            name="Aarav Sharma",
            age=42,
            gender="Male",
            phone="+91 90000 30001",
            disease="Hypertension",
            user_id=patient_user.id,
            doctor_id=doctor.id,
            nurse_id=nurse.id,
        )
        db.add(patient)
        db.commit()

        doctor_row = db.query(Doctor).filter(Doctor.user_id == doctor_user.id).first()
        patient_row = db.query(Patient).filter(Patient.user_id == patient_user.id).first()
        nurse_row = db.query(Nurse).filter(Nurse.user_id == nurse_user.id).first()

        if doctor_row and patient_row and nurse_row:
            db.add_all([
                MedicalRecord(
                    patient_id=patient_row.id,
                    doctor_id=doctor_row.id,
                    nurse_id=nurse_row.id,
                    diagnosis="Hypertension monitoring",
                    advice="Continue low-salt diet and monitor blood pressure twice daily.",
                    medicines="Amlodipine 5mg daily, Vitamin D supplement",
                    notes="Stable condition; regular review required.",
                ),
                Appointment(
                    patient_name=patient_row.name,
                    doctor_name=doctor_row.name,
                    date="2026-09-17",
                    time="09:30 AM",
                    status="Scheduled",
                ),
            ])
            db.commit()

    db.close()

    thread = threading.Thread(target=start_socket_server, daemon=True)
    thread.start()

    yield


app = FastAPI(
    title="Smart Hospital Management & Communication System",
    lifespan=lifespan
)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


def layout_context(request: Request, extra=None):
    user = get_current_user(request)
    context = {
        "user": user,
        "user_name": user.name if user else "",
        "role": user.role.lower() if user else "guest",
        "active_path": request.url.path,
    }
    if extra:
        context.update(extra)
    return context


def enrich_messages(db, messages):
    user_ids = {m.sender_id for m in messages} | {m.receiver_id for m in messages if m.receiver_id}
    users = db.query(User).filter(User.id.in_(user_ids)).all() if user_ids else []
    user_map = {u.id: u.name or u.username for u in users}
    
    patient_ids = {m.patient_id for m in messages if m.patient_id}
    patients = db.query(Patient).filter(Patient.id.in_(patient_ids)).all() if patient_ids else []
    patient_map = {p.id: p.name for p in patients}

    enriched = []
    for m in messages:
        enriched.append({
            "id": m.id,
            "sender_name": user_map.get(m.sender_id, "System"),
            "receiver_name": user_map.get(m.receiver_id, "Anyone"),
            "patient_name": patient_map.get(m.patient_id, "—"),
            "message_type": m.message_type,
            "message": m.message,
            "date": m.date,
            "time": m.time,
            "status": m.status,
            "sender_id": m.sender_id,
            "receiver_id": m.receiver_id,
        })
    return enriched


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = get_current_user(request)
    if user:
        if getattr(user, "must_change_password", 0) == 1:
            return RedirectResponse("/change-password", status_code=303)
        return RedirectResponse(ROLE_REDIRECTS.get(user.role.lower(), "/dashboard"), status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={}
    )


@app.get("/admin-login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    user = get_current_user(request)
    if user:
        if user.role.lower() == "admin":
            return RedirectResponse("/admin-dashboard", status_code=303)
    return templates.TemplateResponse(request=request, name="admin/login.html")


@app.post("/admin-login")
def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    req_username = (username or "").strip()
    user = db.query(User).filter(User.username == req_username).first()
    if not user and req_username.lower() == "administrator":
        user = db.query(User).filter(User.username == "admin").first()

    if user and verify_password(password, user.password):
        if user.role.lower() != "admin":
            db.close()
            return templates.TemplateResponse(
                request=request,
                name="admin/login.html",
                context={
                    "error": f"Access denied: User '{user.username}' is not registered as an Administrator.",
                    "prefill_username": username
                },
                status_code=403
            )
        if getattr(user, "status", "Active") == "Inactive":
            db.close()
            return templates.TemplateResponse(
                request=request,
                name="admin/login.html",
                context={
                    "error": "This administrator account is deactivated. Please contact support.",
                    "prefill_username": username
                },
                status_code=403
            )

        dest = "/change-password" if getattr(user, "must_change_password", 0) == 1 else "/admin-dashboard"
        response = RedirectResponse(dest, status_code=303)
        response.set_cookie(key="user_id", value=str(user.id), httponly=True)
        response.set_cookie(key="username", value=user.username, httponly=True)
        response.set_cookie(key="role", value=user.role, httponly=True)
        response.set_cookie(key="user_name", value=user.name or user.username, httponly=True)
        db.close()
        return response

    db.close()
    return templates.TemplateResponse(
        request=request,
        name="admin/login.html",
        context={
            "error": "Invalid administrator username or password. Please verify your credentials.",
            "prefill_username": username
        },
        status_code=400
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/", status_code=303)
    if getattr(user, "must_change_password", 0) == 1:
        return RedirectResponse("/change-password", status_code=303)
    redirect_url = ROLE_REDIRECTS.get(user.role.lower(), "/")
    return RedirectResponse(redirect_url, status_code=303)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    requested_username = (username or "").strip()
    username_aliases = {
        "admin": ["admin", "administrator"],
        "doctor": ["doctor", "dr_meera"],
        "dr_meera": ["dr_meera", "doctor"],
        "patient": ["patient", "aarav_pat", "patient_aarav"],
        "aarav_pat": ["aarav_pat", "patient", "patient_aarav"],
        "patient_aarav": ["patient_aarav", "aarav_pat", "patient"],
        "nurse": ["nurse", "nurse_priya"],
        "nurse_priya": ["nurse_priya", "nurse"],
    }
    candidate_usernames = username_aliases.get(requested_username.lower(), [requested_username])

    user = db.query(User).filter(User.username == requested_username).first()
    if not user:
        user = db.query(User).filter(User.username.in_(candidate_usernames[1:])).first()

    if user and verify_password(password, user.password):
        if getattr(user, "status", "Active") == "Inactive":
            db.close()
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "error": "This user account has been deactivated. Please contact the hospital administrator.",
                    "prefill_username": username,
                },
                status_code=403
            )

        role = user.role.lower()
        if getattr(user, "must_change_password", 0) == 1:
            dest = "/change-password"
        else:
            dest = ROLE_REDIRECTS.get(role, "/")

        response = RedirectResponse(dest, status_code=303)
        response.set_cookie(key="user_id", value=str(user.id), httponly=True)
        response.set_cookie(key="username", value=user.username, httponly=True)
        response.set_cookie(key="role", value=user.role, httponly=True)
        response.set_cookie(key="user_name", value=user.name or user.username, httponly=True)
        db.close()
        return response

    db.close()
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Invalid username or password. Please verify your credentials and try again.",
            "prefill_username": username,
        },
        status_code=400
    )


@app.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="admin/change_password.html",
        context=layout_context(request, {"user": user})
    )


@app.post("/change-password")
def change_password_submit(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/", status_code=303)

    db = SessionLocal()
    db_user = db.query(User).filter(User.id == user.id).first()
    if not db_user:
        db.close()
        return RedirectResponse("/", status_code=303)

    if not verify_password(current_password, db_user.password):
        db.close()
        return templates.TemplateResponse(
            request=request,
            name="admin/change_password.html",
            context=layout_context(request, {
                "user": user,
                "error": "The current (temporary) password entered is incorrect."
            }),
            status_code=400
        )

    if new_password != confirm_password:
        db.close()
        return templates.TemplateResponse(
            request=request,
            name="admin/change_password.html",
            context=layout_context(request, {
                "user": user,
                "error": "New password and password confirmation do not match."
            }),
            status_code=400
        )

    if len(new_password) < 6:
        db.close()
        return templates.TemplateResponse(
            request=request,
            name="admin/change_password.html",
            context=layout_context(request, {
                "user": user,
                "error": "New password must be at least 6 characters long."
            }),
            status_code=400
        )

    # Hash new password securely with salt and clear must_change_password flag
    db_user.password = hash_password(new_password)
    db_user.must_change_password = 0
    db.commit()
    db.close()

    dest = ROLE_REDIRECTS.get(user.role.lower(), "/dashboard")
    return RedirectResponse(dest, status_code=303)


@app.get("/access-denied", response_class=HTMLResponse)
def access_denied_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="admin/access_denied.html",
        context=layout_context(request),
        status_code=403
    )


@app.get("/admin-dashboard", response_class=HTMLResponse)
def admin_dashboard_page(request: Request):
    user = require_role(request, ["admin"])
    if isinstance(user, RedirectResponse):
        return user

    db = SessionLocal()
    patient_count = db.query(Patient).count()
    doctor_count = db.query(Doctor).count()
    nurse_count = db.query(Nurse).count()
    appointment_count = db.query(Appointment).count()
    total_users = db.query(User).count()
    active_users_count = db.query(User).filter(User.status != "Inactive").count()
    pending_temp_passwords = db.query(User).filter(User.must_change_password == 1).count()

    recent_patients = db.query(Patient).order_by(Patient.id.desc()).limit(5).all()
    recent_doctors = db.query(Doctor).order_by(Doctor.id.desc()).limit(5).all()
    recent_nurses = db.query(Nurse).order_by(Nurse.id.desc()).limit(5).all()

    context = layout_context(request, {
        "admin": user,
        "patient_count": patient_count,
        "doctor_count": doctor_count,
        "nurse_count": nurse_count,
        "appointment_count": appointment_count,
        "total_users": total_users,
        "active_users_count": active_users_count,
        "pending_temp_passwords": pending_temp_passwords,
        "recent_patients": recent_patients,
        "recent_doctors": recent_doctors,
        "recent_nurses": recent_nurses,
    })
    db.close()

    return templates.TemplateResponse(
        request=request,
        name="admin/dashboard.html",
        context=context
    )


@app.get("/admin/patients", response_class=HTMLResponse)
def admin_patients_page(request: Request):
    user = require_role(request, ["admin"])
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="admin/patients.html",
        context=layout_context(request)
    )


@app.get("/admin/doctors", response_class=HTMLResponse)
def admin_doctors_page(request: Request):
    user = require_role(request, ["admin"])
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="admin/doctors.html",
        context=layout_context(request)
    )


@app.get("/admin/nurses", response_class=HTMLResponse)
def admin_nurses_page(request: Request):
    user = require_role(request, ["admin"])
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="admin/nurses.html",
        context=layout_context(request)
    )


@app.get("/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    for key in ["user_id", "username", "role", "user_name"]:
        response.delete_cookie(key)
    return response


@app.get("/api/admin/stats")
def get_admin_stats(request: Request):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin permissions required")

    db = SessionLocal()
    stats = {
        "patients": db.query(Patient).count(),
        "doctors": db.query(Doctor).count(),
        "nurses": db.query(Nurse).count(),
        "appointments": db.query(Appointment).count(),
        "users": db.query(User).count(),
        "pending_temp_passwords": db.query(User).filter(User.must_change_password == 1).count(),
        "active_users": db.query(User).filter(User.status != "Inactive").count(),
    }
    db.close()
    return stats


# ========================================================
# PATIENT RESTful CRUD ENDPOINTS
# ========================================================

@app.get("/api/patients")
def get_patients():
    db = SessionLocal()
    patients = db.query(Patient).all()
    user_ids = [p.user_id for p in patients if p.user_id]
    users_by_id = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        users_by_id = {u.id: u for u in users}

    result = []
    for patient in patients:
        u = users_by_id.get(patient.user_id)
        result.append({
            "id": patient.id,
            "name": patient.name,
            "age": patient.age,
            "gender": patient.gender,
            "phone": patient.phone,
            "disease": patient.disease,
            "address": getattr(patient, "address", "Not Specified") or "Not Specified",
            "hospital_name": getattr(patient, "hospital_name", "Smart Hospital Central") or "Smart Hospital Central",
            "ward": patient.ward or "General",
            "status": getattr(patient, "status", "Active") or "Active",
            "user_id": patient.user_id,
            "username": u.username if u else None,
            "user_status": getattr(u, "status", "Active") if u else "Active",
            "must_change_password": bool(getattr(u, "must_change_password", 0)) if u else False,
            "doctor_id": patient.doctor_id,
            "nurse_id": patient.nurse_id,
        })

    db.close()
    return result


@app.get("/api/patients/{patient_id}")
def get_patient(patient_id: int):
    db = SessionLocal()
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        db.close()
        raise HTTPException(status_code=404, detail="Patient not found")

    u = db.query(User).filter(User.id == patient.user_id).first() if patient.user_id else None
    data = {
        "id": patient.id,
        "name": patient.name,
        "age": patient.age,
        "gender": patient.gender,
        "phone": patient.phone,
        "disease": patient.disease,
        "address": getattr(patient, "address", "Not Specified") or "Not Specified",
        "hospital_name": getattr(patient, "hospital_name", "Smart Hospital Central") or "Smart Hospital Central",
        "ward": patient.ward or "General",
        "status": getattr(patient, "status", "Active") or "Active",
        "user_id": patient.user_id,
        "username": u.username if u else None,
        "must_change_password": bool(getattr(u, "must_change_password", 0)) if u else False,
        "doctor_id": patient.doctor_id,
        "nurse_id": patient.nurse_id,
    }
    db.close()
    return data


@app.post("/api/patients", status_code=201)
def add_patient(request: Request, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")

    name = (data.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Patient name is required")

    age = data.get("age")
    try:
        age = int(age)
        if age <= 0 or age > 130:
            raise ValueError()
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Patient age must be a valid number between 1 and 130")

    phone = (data.get("phone") or "").strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number is required")

    address = (data.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")

    hospital_name = (data.get("hospital_name") or "Smart Hospital Central").strip()

    db = SessionLocal()
    created_user_id = None
    username = (data.get("username") or "").strip()
    temp_password = data.get("temporary_password")

    if username:
        existing = db.query(User).filter(User.username.ilike(username)).first()
        if existing:
            db.close()
            raise HTTPException(status_code=400, detail=f"Username '{username}' is already taken. Please choose another username.")

        if not temp_password or len(str(temp_password).strip()) < 6:
            db.close()
            raise HTTPException(status_code=400, detail="A temporary password of at least 6 characters is required")

        new_user = User(
            username=username,
            password=hash_password(str(temp_password).strip()),
            name=name,
            email=data.get("email") or f"{username}@smart-hospital.local",
            role="patient",
            must_change_password=1,
            status="Active",
        )
        db.add(new_user)
        db.flush()
        created_user_id = new_user.id

    patient = Patient(
        name=name,
        age=age,
        gender=data.get("gender", "Male"),
        phone=phone,
        disease=data.get("disease", "General Care"),
        address=address,
        hospital_name=hospital_name,
        ward=data.get("ward", "General"),
        status=data.get("status", "Active"),
        user_id=created_user_id,
        doctor_id=data.get("doctor_id"),
        nurse_id=data.get("nurse_id"),
    )

    db.add(patient)
    db.commit()
    db.refresh(patient)
    pid = patient.id
    db.close()

    return {
        "message": "Patient created successfully" + (" with temporary credentials" if created_user_id else ""),
        "patient_id": pid,
        "user_id": created_user_id,
    }


@app.put("/api/patients/{patient_id}")
def update_patient(request: Request, patient_id: int, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")
    db = SessionLocal()
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        db.close()
        raise HTTPException(status_code=404, detail="Patient not found")

    if "name" in data and data["name"].strip():
        patient.name = data["name"].strip()
    if "age" in data and data["age"] is not None:
        try:
            patient.age = int(data["age"])
        except ValueError:
            pass
    if "gender" in data:
        patient.gender = data["gender"]
    if "phone" in data and data["phone"].strip():
        patient.phone = data["phone"].strip()
    if "disease" in data:
        patient.disease = data["disease"].strip()
    if "address" in data and data["address"].strip():
        patient.address = data["address"].strip()
    if "hospital_name" in data and data["hospital_name"].strip():
        patient.hospital_name = data["hospital_name"].strip()
    if "ward" in data:
        patient.ward = data["ward"]
    if "status" in data:
        patient.status = data["status"]
        if patient.user_id:
            u = db.query(User).filter(User.id == patient.user_id).first()
            if u:
                u.status = data["status"]

    if patient.user_id and "name" in data and data["name"].strip():
        u = db.query(User).filter(User.id == patient.user_id).first()
        if u:
            u.name = patient.name

    db.commit()
    db.close()

    return {"message": "Patient updated successfully"}


@app.delete("/api/patients/{patient_id}")
def delete_patient(request: Request, patient_id: int):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")
    db = SessionLocal()
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        db.close()
        raise HTTPException(status_code=404, detail="Patient not found")

    user_id = patient.user_id
    db.delete(patient)
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.delete(user)

    db.commit()
    db.close()

    return {"message": "Patient deleted successfully"}


# ========================================================
# DOCTOR RESTful CRUD ENDPOINTS
# ========================================================

@app.get("/api/doctors")
def get_doctors():
    db = SessionLocal()
    doctors = db.query(Doctor).all()
    user_ids = [d.user_id for d in doctors if d.user_id]
    users_by_id = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        users_by_id = {u.id: u for u in users}

    result = []
    for doctor in doctors:
        u = users_by_id.get(doctor.user_id)
        result.append({
            "id": doctor.id,
            "name": doctor.name,
            "age": getattr(doctor, "age", None),
            "address": getattr(doctor, "address", "Not Specified") or "Not Specified",
            "hospital_name": getattr(doctor, "hospital_name", "Smart Hospital Central") or "Smart Hospital Central",
            "specialization": doctor.specialization,
            "department": getattr(doctor, "department", "General") or "General",
            "phone": doctor.phone,
            "shift": getattr(doctor, "shift", "Morning") or "Morning",
            "status": getattr(doctor, "status", "Active") or "Active",
            "user_id": doctor.user_id,
            "username": u.username if u else None,
            "user_status": getattr(u, "status", "Active") if u else "Active",
            "must_change_password": bool(getattr(u, "must_change_password", 0)) if u else False,
        })

    db.close()
    return result


@app.get("/api/doctors/{doctor_id}")
def get_doctor(doctor_id: int):
    db = SessionLocal()
    doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
    if not doctor:
        db.close()
        raise HTTPException(status_code=404, detail="Doctor not found")

    u = db.query(User).filter(User.id == doctor.user_id).first() if doctor.user_id else None
    data = {
        "id": doctor.id,
        "name": doctor.name,
        "age": getattr(doctor, "age", None),
        "address": getattr(doctor, "address", "Not Specified") or "Not Specified",
        "hospital_name": getattr(doctor, "hospital_name", "Smart Hospital Central") or "Smart Hospital Central",
        "specialization": doctor.specialization,
        "department": getattr(doctor, "department", "General") or "General",
        "phone": doctor.phone,
        "shift": getattr(doctor, "shift", "Morning") or "Morning",
        "status": getattr(doctor, "status", "Active") or "Active",
        "user_id": doctor.user_id,
        "username": u.username if u else None,
        "must_change_password": bool(getattr(u, "must_change_password", 0)) if u else False,
    }
    db.close()
    return data


@app.post("/api/doctors", status_code=201)
def add_doctor(request: Request, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")

    name = (data.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Doctor name is required")

    specialization = (data.get("specialization") or "").strip()
    if not specialization:
        raise HTTPException(status_code=400, detail="Specialization is required")

    phone = (data.get("phone") or "").strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number is required")

    address = (data.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")

    hospital_name = (data.get("hospital_name") or "Smart Hospital Central").strip()

    age = data.get("age")
    if age is not None and str(age).strip() != "":
        try:
            age = int(age)
        except ValueError:
            age = None
    else:
        age = None

    db = SessionLocal()
    created_user_id = None
    username = (data.get("username") or "").strip()
    temp_password = data.get("temporary_password")

    if username:
        existing = db.query(User).filter(User.username.ilike(username)).first()
        if existing:
            db.close()
            raise HTTPException(status_code=400, detail=f"Username '{username}' is already in use")

        if not temp_password or len(str(temp_password).strip()) < 6:
            db.close()
            raise HTTPException(status_code=400, detail="A temporary password of at least 6 characters is required")

        new_user = User(
            username=username,
            password=hash_password(str(temp_password).strip()),
            name=name,
            email=data.get("email") or f"{username}@smart-hospital.local",
            role="doctor",
            must_change_password=1,
            status="Active",
        )
        db.add(new_user)
        db.flush()
        created_user_id = new_user.id

    doctor = Doctor(
        name=name,
        age=age,
        address=address,
        hospital_name=hospital_name,
        specialization=specialization,
        department=data.get("department", "General"),
        phone=phone,
        shift=data.get("shift", "Morning"),
        status=data.get("status", "Active"),
        user_id=created_user_id,
    )

    db.add(doctor)
    db.commit()
    db.refresh(doctor)
    did = doctor.id
    db.close()

    return {
        "message": "Doctor added successfully" + (" with temporary credentials" if created_user_id else ""),
        "doctor_id": did,
        "user_id": created_user_id,
    }


@app.put("/api/doctors/{doctor_id}")
def update_doctor(request: Request, doctor_id: int, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")
    db = SessionLocal()
    doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
    if not doctor:
        db.close()
        raise HTTPException(status_code=404, detail="Doctor not found")

    if "name" in data and data["name"].strip():
        doctor.name = data["name"].strip()
    if "age" in data:
        try:
            doctor.age = int(data["age"]) if data["age"] is not None and str(data["age"]).strip() != "" else None
        except ValueError:
            pass
    if "specialization" in data and data["specialization"].strip():
        doctor.specialization = data["specialization"].strip()
    if "phone" in data and data["phone"].strip():
        doctor.phone = data["phone"].strip()
    if "address" in data and data["address"].strip():
        doctor.address = data["address"].strip()
    if "hospital_name" in data and data["hospital_name"].strip():
        doctor.hospital_name = data["hospital_name"].strip()
    if "department" in data:
        doctor.department = data["department"]
    if "shift" in data:
        doctor.shift = data["shift"]
    if "status" in data:
        doctor.status = data["status"]
        if doctor.user_id:
            u = db.query(User).filter(User.id == doctor.user_id).first()
            if u:
                u.status = data["status"]

    if doctor.user_id and "name" in data and data["name"].strip():
        u = db.query(User).filter(User.id == doctor.user_id).first()
        if u:
            u.name = doctor.name

    db.commit()
    db.close()

    return {"message": "Doctor updated successfully"}


@app.delete("/api/doctors/{doctor_id}")
def delete_doctor(request: Request, doctor_id: int):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")
    db = SessionLocal()
    doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
    if not doctor:
        db.close()
        raise HTTPException(status_code=404, detail="Doctor not found")

    user_id = doctor.user_id
    db.delete(doctor)
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.delete(user)

    db.commit()
    db.close()

    return {"message": "Doctor deleted successfully"}


# ========================================================
# NURSE RESTful CRUD ENDPOINTS
# ========================================================

@app.get("/api/nurses")
def get_nurses():
    db = SessionLocal()
    nurses = db.query(Nurse).all()
    user_ids = [n.user_id for n in nurses if n.user_id]
    users_by_id = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        users_by_id = {u.id: u for u in users}

    result = []
    for nurse in nurses:
        u = users_by_id.get(nurse.user_id)
        result.append({
            "id": nurse.id,
            "name": nurse.name,
            "age": getattr(nurse, "age", None),
            "address": getattr(nurse, "address", "Not Specified") or "Not Specified",
            "hospital_name": getattr(nurse, "hospital_name", "Smart Hospital Central") or "Smart Hospital Central",
            "department": nurse.department,
            "shift": getattr(nurse, "shift", "Morning") or "Morning",
            "phone": nurse.phone,
            "status": getattr(nurse, "status", "Active") or "Active",
            "user_id": nurse.user_id,
            "username": u.username if u else None,
            "user_status": getattr(u, "status", "Active") if u else "Active",
            "must_change_password": bool(getattr(u, "must_change_password", 0)) if u else False,
        })

    db.close()
    return result


@app.get("/api/nurses/{nurse_id}")
def get_nurse(nurse_id: int):
    db = SessionLocal()
    nurse = db.query(Nurse).filter(Nurse.id == nurse_id).first()
    if not nurse:
        db.close()
        raise HTTPException(status_code=404, detail="Nurse not found")

    u = db.query(User).filter(User.id == nurse.user_id).first() if nurse.user_id else None
    data = {
        "id": nurse.id,
        "name": nurse.name,
        "age": getattr(nurse, "age", None),
        "address": getattr(nurse, "address", "Not Specified") or "Not Specified",
        "hospital_name": getattr(nurse, "hospital_name", "Smart Hospital Central") or "Smart Hospital Central",
        "department": nurse.department,
        "shift": getattr(nurse, "shift", "Morning") or "Morning",
        "phone": nurse.phone,
        "status": getattr(nurse, "status", "Active") or "Active",
        "user_id": nurse.user_id,
        "username": u.username if u else None,
        "must_change_password": bool(getattr(u, "must_change_password", 0)) if u else False,
    }
    db.close()
    return data


@app.post("/api/nurses", status_code=201)
def add_nurse(request: Request, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")

    name = (data.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Nurse name is required")

    department = (data.get("department") or "").strip()
    if not department:
        raise HTTPException(status_code=400, detail="Department is required")

    phone = (data.get("phone") or "").strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number is required")

    address = (data.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")

    hospital_name = (data.get("hospital_name") or "Smart Hospital Central").strip()

    age = data.get("age")
    if age is not None and str(age).strip() != "":
        try:
            age = int(age)
        except ValueError:
            age = None
    else:
        age = None

    db = SessionLocal()
    created_user_id = None
    username = (data.get("username") or "").strip()
    temp_password = data.get("temporary_password")

    if username:
        existing = db.query(User).filter(User.username.ilike(username)).first()
        if existing:
            db.close()
            raise HTTPException(status_code=400, detail=f"Username '{username}' is already in use")

        if not temp_password or len(str(temp_password).strip()) < 6:
            db.close()
            raise HTTPException(status_code=400, detail="A temporary password of at least 6 characters is required")

        new_user = User(
            username=username,
            password=hash_password(str(temp_password).strip()),
            name=name,
            email=data.get("email") or f"{username}@smart-hospital.local",
            role="nurse",
            must_change_password=1,
            status="Active",
        )
        db.add(new_user)
        db.flush()
        created_user_id = new_user.id

    nurse = Nurse(
        name=name,
        age=age,
        address=address,
        hospital_name=hospital_name,
        department=department,
        shift=data.get("shift", "Morning"),
        phone=phone,
        status=data.get("status", "Active"),
        user_id=created_user_id,
    )

    db.add(nurse)
    db.commit()
    db.refresh(nurse)
    nid = nurse.id
    db.close()

    return {
        "message": "Nurse added successfully" + (" with temporary credentials" if created_user_id else ""),
        "nurse_id": nid,
        "user_id": created_user_id,
    }


@app.put("/api/nurses/{nurse_id}")
def update_nurse(request: Request, nurse_id: int, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")
    db = SessionLocal()
    nurse = db.query(Nurse).filter(Nurse.id == nurse_id).first()
    if not nurse:
        db.close()
        raise HTTPException(status_code=404, detail="Nurse not found")

    if "name" in data and data["name"].strip():
        nurse.name = data["name"].strip()
    if "age" in data:
        try:
            nurse.age = int(data["age"]) if data["age"] is not None and str(data["age"]).strip() != "" else None
        except ValueError:
            pass
    if "department" in data and data["department"].strip():
        nurse.department = data["department"].strip()
    if "phone" in data and data["phone"].strip():
        nurse.phone = data["phone"].strip()
    if "address" in data and data["address"].strip():
        nurse.address = data["address"].strip()
    if "hospital_name" in data and data["hospital_name"].strip():
        nurse.hospital_name = data["hospital_name"].strip()
    if "shift" in data:
        nurse.shift = data["shift"]
    if "status" in data:
        nurse.status = data["status"]
        if nurse.user_id:
            u = db.query(User).filter(User.id == nurse.user_id).first()
            if u:
                u.status = data["status"]

    if nurse.user_id and "name" in data and data["name"].strip():
        u = db.query(User).filter(User.id == nurse.user_id).first()
        if u:
            u.name = nurse.name

    db.commit()
    db.close()

    return {"message": "Nurse updated successfully"}


@app.delete("/api/nurses/{nurse_id}")
def delete_nurse(request: Request, nurse_id: int):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")
    db = SessionLocal()
    nurse = db.query(Nurse).filter(Nurse.id == nurse_id).first()
    if not nurse:
        db.close()
        raise HTTPException(status_code=404, detail="Nurse not found")

    user_id = nurse.user_id
    db.delete(nurse)
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.delete(user)

    db.commit()
    db.close()

    return {"message": "Nurse deleted successfully"}


@app.get("/api/appointments")
def get_appointments():

    db = SessionLocal()

    appointments = db.query(
        Appointment
    ).all()

    result = []

    for appointment in appointments:

        result.append({
            "id": appointment.id,
            "patient_name": appointment.patient_name,
            "doctor_name": appointment.doctor_name,
            "date": appointment.date,
            "time": appointment.time,
            "status": appointment.status
        })

    db.close()

    return result


@app.post("/api/appointments")
def add_appointment(request: Request, data: dict):
    user = get_current_user(request)
    if not user or user.role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Not authorized. Admin only.")

    db = SessionLocal()

    appointment = Appointment(
        patient_name=data["patient_name"],
        doctor_name=data["doctor_name"],
        date=data["date"],
        time=data["time"],
        status="Scheduled"
    )

    db.add(appointment)
    db.commit()
    db.refresh(appointment)

    db.close()

    return {
        "message": "Appointment created successfully",
        "appointment_id": appointment.id
    }


@app.get("/api/medical-records")
def get_medical_records():

    db = SessionLocal()

    records = db.query(
        MedicalRecord
    ).all()

    result = []

    for record in records:
        patient = db.query(Patient).filter(Patient.id == record.patient_id).first()
        doctor = db.query(Doctor).filter(Doctor.id == record.doctor_id).first()

        result.append({
            "id": record.id,
            "patient_id": record.patient_id,
            "patient_name": patient.name if patient else None,
            "doctor_id": record.doctor_id,
            "doctor_name": doctor.name if doctor else None,
            "diagnosis": record.diagnosis,
            "advice": record.advice,
            "medicines": record.medicines,
            "prescription": record.medicines,
            "notes": record.notes,
        })

    db.close()

    return result


@app.post("/api/medical-records")
def add_medical_record(data: dict):

    db = SessionLocal()
    patient_id = data.get("patient_id")
    if not patient_id and data.get("patient_name"):
        patient = db.query(Patient).filter(Patient.name == data["patient_name"]).first()
        patient_id = patient.id if patient else None

    doctor_id = data.get("doctor_id")
    if not doctor_id and data.get("doctor_name"):
        doctor = db.query(Doctor).filter(Doctor.name == data["doctor_name"]).first()
        doctor_id = doctor.id if doctor else None

    if not patient_id or not doctor_id:
        db.close()
        raise HTTPException(status_code=400, detail="patient_id and doctor_id are required")

    record = MedicalRecord(
        patient_id=patient_id,
        doctor_id=doctor_id,
        nurse_id=data.get("nurse_id"),
        diagnosis=data.get("diagnosis"),
        advice=data.get("advice"),
        medicines=data.get("medicines", data.get("prescription")),
        notes=data.get("notes"),
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    db.close()

    return {
        "message": "Medical record added successfully",
        "record_id": record.id
    }


@app.post("/api/messages")
def send_message(request: Request, data: dict):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    db = SessionLocal()
    receiver_id = data.get("receiver_id")
    if receiver_id:
        try:
            receiver_id = int(receiver_id)
        except ValueError:
            receiver_id = None

    patient_id = data.get("patient_id")
    if patient_id:
        try:
            patient_id = int(patient_id)
        except ValueError:
            patient_id = None
            
    message_type = data.get("message_type", "General")
    content = data.get("message", "")
    date_str = data.get("date", "")
    time_str = data.get("time", "")

    new_msg = Message(
        sender_id=user.id,
        receiver_id=receiver_id,
        patient_id=patient_id,
        message_type=message_type,
        message=content,
        date=date_str,
        time=time_str,
        status="Unread"
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    
    msg_id = new_msg.id
    db.close()
    
    return {"message": "Message sent successfully", "id": msg_id}


@app.post("/api/test-json")
def test_json(data: dict):

    return {
        "received": data,
        "message": "JSON received successfully"
    }


@app.get("/patients", response_class=HTMLResponse)
def patients_page(request: Request):
    user = require_role(request, ["admin", "doctor", "nurse"])
    if isinstance(user, RedirectResponse):
        return user
    
    return templates.TemplateResponse(
        request=request,
        name="admin/patients.html",
        context=layout_context(request),
    )



@app.get("/doctors", response_class=HTMLResponse)
def doctors_page(request: Request):
    user = require_role(request, ["admin", "doctor", "nurse"])
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="admin/doctors.html",
        context=layout_context(request),
    )


@app.get("/nurses", response_class=HTMLResponse)
def nurses_page(request: Request):
    user = require_role(request, ["admin", "doctor", "nurse"])
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="admin/nurses.html",
        context=layout_context(request),
    )


@app.get("/appointments", response_class=HTMLResponse)
@app.get("/admin/appointments", response_class=HTMLResponse)
def appointments_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="admin/appointments.html",
        context=layout_context(request),
    )


@app.get("/communication", response_class=HTMLResponse)
@app.get("/admin/communication", response_class=HTMLResponse)
def communication_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="admin/communication.html",
        context=layout_context(request),
    )



@app.get("/api/doctor/dashboard")
def doctor_dashboard(request: Request):
    user = require_role(request, ["doctor"])
    if isinstance(user, RedirectResponse):
        return {"error": "Doctor login required"}

    db = SessionLocal()

    doctor = db.query(Doctor).filter(Doctor.user_id == user.id).first()
    if not doctor:
        db.close()
        return {"error": "Doctor not found"}

    patients = db.query(Patient).filter(Patient.doctor_id == doctor.id).all()
    result = []

    for patient in patients:
        nurse = db.query(Nurse).filter(Nurse.id == patient.nurse_id).first() if patient.nurse_id else None
        records = db.query(MedicalRecord).filter(MedicalRecord.patient_id == patient.id, MedicalRecord.doctor_id == doctor.id).all()

        medical_records = []
        for record in records:
            medical_records.append({
                "diagnosis": record.diagnosis,
                "advice": record.advice,
                "medicines": record.medicines,
                "notes": record.notes
            })

        result.append({
            "patient_id": patient.id,
            "patient_name": patient.name,
            "age": patient.age,
            "gender": patient.gender,
            "phone": patient.phone,
            "disease": patient.disease,
            "nurse": {
                "id": nurse.id,
                "name": nurse.name,
                "department": nurse.department,
                "phone": nurse.phone
            } if nurse else None,
            "medical_records": medical_records,
        })

    db.close()
    return {
        "doctor": {
            "id": doctor.id,
            "name": doctor.name,
            "specialization": doctor.specialization,
            "phone": doctor.phone,
        },
        "patients": result,
    }


@app.get("/doctor-dashboard", response_class=HTMLResponse)
def doctor_dashboard_page(request: Request):
    user = require_role(request, ["doctor"])
    if isinstance(user, RedirectResponse):
        return user

    db = SessionLocal()
    doctor = db.query(Doctor).filter(Doctor.user_id == user.id).first()
    if not doctor:
        db.close()
        return RedirectResponse("/", status_code=303)
    appointments = db.query(Appointment).filter(
        or_(Appointment.doctor_id == doctor.id, Appointment.doctor_name == doctor.name)
    ).order_by(Appointment.id.desc()).all()

    upcoming_appointments = []
    completed_appointments = []
    for appt in appointments:
        if appt.status.lower() in ["scheduled", "confirmed", "upcoming"]:
            upcoming_appointments.append(appt)
        else:
            completed_appointments.append(appt)

    patient_ids = {appt.patient_id for appt in appointments if appt.patient_id}
    patient_names = {appt.patient_name for appt in appointments if appt.patient_name}
    
    patients = db.query(Patient).filter(
        or_(Patient.id.in_(patient_ids), Patient.name.in_(patient_names))
    ).all() if (patient_ids or patient_names) else []
    nurse_ids = {p.nurse_id for p in patients if p.nurse_id}
    nurses = db.query(Nurse).filter(Nurse.id.in_(nurse_ids)).all() if nurse_ids else []

    all_nurses = db.query(Nurse).all()

    messages_qs = db.query(Message).filter(
        or_(
            Message.receiver_id == user.id, 
            Message.sender_id == user.id
        )
    ).order_by(Message.id.desc()).all()
    enriched_messages = enrich_messages(db, messages_qs)

    db.close()

    return templates.TemplateResponse(
        request=request,
        name="doctor_dashboard.html",
        context=layout_context(request, {
            "doctor": doctor,
            "upcoming_appointments": upcoming_appointments,
            "completed_appointments": completed_appointments,
            "patients": patients,
            "nurses": nurses,
            "all_nurses": all_nurses,
            "appointments": appointments,
            "messages": enriched_messages,
        }),
    )


@app.post("/doctor/complete-appointment")
def complete_appointment(request: Request, appointment_id: int = Form(...)):
    user = require_role(request, ["doctor"])
    if isinstance(user, RedirectResponse):
        return user
    
    db = SessionLocal()
    appt = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if appt:
        appt.status = "Completed"
        db.commit()
    db.close()
    return RedirectResponse("/doctor-dashboard", status_code=303)


@app.post("/doctor/add-advice")
def doctor_add_advice(
    request: Request,
    appointment_id: int = Form(...),
    advice: str = Form(...)
):
    user = require_role(request, ["doctor"])
    if isinstance(user, RedirectResponse):
        return user
    
    db = SessionLocal()
    doctor = db.query(Doctor).filter(Doctor.user_id == user.id).first()
    appt = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    
    if doctor and appt:
        patient = db.query(Patient).filter(Patient.name == appt.patient_name).first()
        record = MedicalRecord(
            patient_id=patient.id if patient else None,
            doctor_id=doctor.id,
            diagnosis=appt.reason or "Follow-up",
            advice=advice,
            medicines="See Advice",
            notes=f"Added on {appt.date}"
        )
        db.add(record)
        db.commit()
    
    db.close()
    return RedirectResponse("/doctor-dashboard", status_code=303)



@app.get("/patient-dashboard", response_class=HTMLResponse)
def patient_dashboard_page(request: Request):
    user = require_role(request, ["patient"])
    if isinstance(user, RedirectResponse):
        return user

    db = SessionLocal()
    patient = db.query(Patient).filter(Patient.user_id == user.id).first()
    if not patient:
        db.close()
        return RedirectResponse("/", status_code=303)

    all_doctors = db.query(Doctor).all()
    appointments = db.query(Appointment).filter(Appointment.patient_name == patient.name).order_by(Appointment.id.desc()).all()
    
    current_appointment = None
    visit_history = []
    
    for appt in appointments:
        if appt.status.lower() in ["scheduled", "confirmed", "upcoming"]:
            if not current_appointment:
                current_appointment = appt
            else:
                visit_history.append(appt)
        visit_history.append(appt)

    messages_qs = db.query(Message).filter(
        or_(
            Message.receiver_id == user.id, 
            Message.sender_id == user.id,
            Message.patient_id == patient.id
        )
    ).order_by(Message.id.desc()).all()
    
    # Filter out doctor->nurse messages unless they are specifically meant for patient too (if needed, but usually patient shouldn't see doc->nurse unless visible_to_patient. For now, keep it simple: patient sees messages where they are sender or receiver, plus Doctor Advice.)
    patient_messages = [m for m in messages_qs if m.message_type in ("Doctor Advice", "Patient -> Doctor", "Doctor -> Patient")]
    
    enriched_messages = enrich_messages(db, patient_messages)

    db.close()

    return templates.TemplateResponse(
        request=request,
        name="patient_dashboard.html",
        context=layout_context(request, {
            "patient": patient,
            "all_doctors": all_doctors,
            "current_appointment": current_appointment,
            "visit_history": visit_history,
            "messages": enriched_messages,
        }),
    )


@app.post("/patient/book-appointment")
def book_appointment(
    request: Request,
    doctor_id: int = Form(...),
    date: str = Form(...),
    time: str = Form(...),
    reason: str = Form(...)
):
    user = require_role(request, ["patient"])
    if isinstance(user, RedirectResponse):
        return user

    db = SessionLocal()
    patient = db.query(Patient).filter(Patient.user_id == user.id).first()
    if not patient:
        db.close()
        return RedirectResponse("/", status_code=303)
        
    doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
    if not doctor:
        db.close()
        return RedirectResponse("/patient-dashboard", status_code=303)

    new_appt = Appointment(
        patient_name=patient.name,
        doctor_name=doctor.name,
        date=date,
        time=time,
        status="Scheduled",
        reason=reason,
        doctor_id=doctor.id,
        patient_id=patient.id
    )
    db.add(new_appt)
    db.commit()
    db.close()
    
    return RedirectResponse("/patient-dashboard", status_code=303)


@app.get("/nurse-dashboard", response_class=HTMLResponse)
def nurse_dashboard_page(request: Request):
    user = require_role(request, ["nurse"])
    if isinstance(user, RedirectResponse):
        return user

    db = SessionLocal()
    nurse = db.query(Nurse).filter(Nurse.user_id == user.id).first()
    if not nurse:
        db.close()
        return RedirectResponse("/", status_code=303)

    patients = db.query(Patient).filter(Patient.nurse_id == nurse.id).all()
    
    doctors = db.query(Doctor).all()
    doctor_map = {d.id: d.name for d in doctors}

    for patient in patients:
        patient.doctor_name_display = doctor_map.get(patient.doctor_id, "—")

    records = []
    for patient in patients:
        record = db.query(MedicalRecord).filter(MedicalRecord.patient_id == patient.id).order_by(MedicalRecord.id.desc()).first()
        if record:
            records.append({
                "patient_name": patient.name,
                "assigned_doctor": patient.doctor_name_display,
                "room_ward": patient.ward or "General",
                "diagnosis": record.diagnosis,
                "medicines": record.medicines,
                "advice": record.advice,
                "notes": record.notes,
            })
            
    patient_names = [p.name for p in patients]
    appointments = db.query(Appointment).filter(Appointment.patient_name.in_(patient_names)).order_by(Appointment.id.desc()).all() if patient_names else []

    messages_qs = db.query(Message).filter(
        or_(
            Message.receiver_id == user.id, 
            Message.sender_id == user.id,
            Message.patient_id.in_([p.id for p in patients])
        )
    ).order_by(Message.id.desc()).all()
    
    # Filter for nurse: sees messages where they are sender/receiver, or doctor->nurse for their patients
    nurse_messages = [m for m in messages_qs if m.message_type in ("Doctor -> Nurse", "Nurse -> Doctor", "Nurse -> Patient")]
    enriched_messages = enrich_messages(db, nurse_messages)

    db.close()

    return templates.TemplateResponse(
        request=request,
        name="nurse_dashboard.html",
        context=layout_context(request, {
            "nurse": nurse,
            "user_email": user.email,
            "patients": patients,
            "all_doctors": doctors,
            "records": records,
            "appointments": appointments,
            "messages": enriched_messages,
        }),
    )