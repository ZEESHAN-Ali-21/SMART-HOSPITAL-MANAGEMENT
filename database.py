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

if __name__ == "__main__":
    conn = sqlite3.connect("hospital.db")
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    for table in tables:
        table_name = table[0]

        print("\n" + "=" * 80)
        print("TABLE:", table_name)
        print("=" * 80)

        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [column[1] for column in cursor.fetchall()]

        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()

        if not rows:
            print("No data stored.")
            continue

        print(" | ".join(columns))
        print("-" * 80)

        for row in rows:
            print(" | ".join(str(value) for value in row))

    conn.close()