import os
import time
import json
import hmac
import base64
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, field_validator


DB_PATH = os.getenv("EXAM_DATABASE", "online_exam.db")
SECRET_KEY = os.getenv("SECRET_KEY", "local-development-secret-change-before-deploy")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com").lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "AdminPass2026!")

app = FastAPI(title="Online Exam API", version="1.0.0")
bearer = HTTPBearer(auto_error=False)


# ---------- DATABASE ----------

def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def get_db():
    db = connect_db()
    try:
        yield db
    finally:
        db.close()


def now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    db = connect_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','student')),
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft'
            CHECK(status IN ('draft','published')),
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        position INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS choices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        is_correct INTEGER NOT NULL CHECK(is_correct IN (0,1))
    );

    CREATE TABLE IF NOT EXISTS attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        exam_id INTEGER NOT NULL REFERENCES exams(id),
        started_at TEXT NOT NULL,
        completed_at TEXT,
        correct_count INTEGER,
        total_questions INTEGER,
        percent REAL,
        UNIQUE(user_id, exam_id)
    );

    CREATE TABLE IF NOT EXISTS answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
        question_id INTEGER NOT NULL REFERENCES questions(id),
        choice_id INTEGER NOT NULL REFERENCES choices(id),
        UNIQUE(attempt_id, question_id)
    );
    """)
    db.commit()

    admin = db.execute(
        "SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,)
    ).fetchone()

    if not admin:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", ADMIN_PASSWORD.encode(), salt, 250000
        )
        db.execute("""
            INSERT INTO users(full_name,email,password_hash,role,created_at)
            VALUES(?,?,?,?,?)
        """, ("Administrator", ADMIN_EMAIL, salt.hex() + ":" + digest.hex(),
              "admin", now()))
        db.commit()
    db.close()


init_db()


# ---------- PASSWORD AND TOKEN ----------

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 250000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 250000
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_token(user_id):
    payload = b64(json.dumps({
        "uid": user_id, "exp": int(time.time()) + 43200
    }).encode())
    signature = hmac.new(
        SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).digest()
    return payload + "." + b64(signature)


def decode_token(token):
    try:
        payload_part, signature = token.split(".", 1)
        expected = b64(hmac.new(
            SECRET_KEY.encode(), payload_part.encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError()

        raw = payload_part + "=" * (-len(payload_part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()))
        if int(payload["exp"]) <= int(time.time()):
            raise HTTPException(status_code=401, detail="Token muddati tugagan")
        return int(payload["uid"])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Token yaroqsiz")


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db=Depends(get_db),
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Avval login qiling")
    uid = decode_token(credentials.credentials)
    user = db.execute(
        "SELECT id,full_name,email,role FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
    return dict(user)


def admin_only(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Faqat admin uchun")
    return user


# ---------- REQUEST SCHEMAS ----------

class RegisterIn(BaseModel):
    full_name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ExamIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""


class ChoiceIn(BaseModel):
    text: str = Field(min_length=1, max_length=500)
    is_correct: bool = False


class QuestionIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    choices: list[ChoiceIn]

    @field_validator("choices")
    @classmethod
    def check_choices(cls, choices):
        if len(choices) != 4:
            raise ValueError("Har savolda aynan 4 ta variant bo'lishi kerak")
        if sum(c.is_correct for c in choices) != 1:
            raise ValueError("Aynan bitta variant to'g'ri bo'lishi kerak")
        return choices


class AnswerIn(BaseModel):
    question_id: int = Field(gt=0)
    choice_id: int = Field(gt=0)


# ---------- HELPERS ----------

def get_exam(db, exam_id):
    exam = db.execute("SELECT * FROM exams WHERE id=?", (exam_id,)).fetchone()
    if not exam:
        raise HTTPException(status_code=404, detail="Test topilmadi")
    return exam


def get_draft_exam(db, exam_id):
    exam = get_exam(db, exam_id)
    if exam["status"] != "draft":
        raise HTTPException(status_code=409, detail="E'lon qilingan test o'zgarmaydi")
    return exam


def get_question(db, exam_id, question_id):
    q = db.execute(
        "SELECT * FROM questions WHERE id=? AND exam_id=?",
        (question_id, exam_id)
    ).fetchone()
    if not q:
        raise HTTPException(status_code=404, detail="Savol topilmadi")
    return q


def public_question(db, q):
    # Studentga to'g'ri javob belgisi yoki is_correct chiqarilmaydi.
    choices = db.execute(
        "SELECT id,text FROM choices WHERE question_id=? ORDER BY id",
        (q["id"],)
    ).fetchall()
    return {
        "id": q["id"],
        "text": q["text"],
        "choices": [dict(c) for c in choices],
    }


def get_attempt(db, attempt_id, user_id):
    attempt = db.execute(
        "SELECT * FROM attempts WHERE id=? AND user_id=?",
        (attempt_id, user_id)
    ).fetchone()
    if not attempt:
        raise HTTPException(status_code=404, detail="Urinish topilmadi")
    return attempt


# ---------- AUTH ----------

@app.get("/")
def home():
    return {"message": "Online Exam API ishlayapti"}


@app.post("/auth/register", status_code=201)
def register(data: RegisterIn, db=Depends(get_db)):
    email = str(data.email).lower()
    try:
        cur = db.execute("""
            INSERT INTO users(full_name,email,password_hash,role,created_at)
            VALUES(?,?,?,?,?)
        """, (data.full_name.strip(), email, hash_password(data.password),
              "student", now()))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email allaqachon mavjud")
    return {
        "id": cur.lastrowid, "full_name": data.full_name,
        "email": email, "role": "student"
    }


@app.post("/auth/login")
def login(data: LoginIn, db=Depends(get_db)):
    user = db.execute(
        "SELECT * FROM users WHERE email=?", (str(data.email).lower(),)
    ).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email yoki parol noto'g'ri")
    return {
        "access_token": create_token(user["id"]),
        "token_type": "bearer",
        "user": {
            "id": user["id"], "full_name": user["full_name"],
            "email": user["email"], "role": user["role"]
        }
    }


@app.get("/auth/me")
def me(user=Depends(current_user)):
    return user


# ---------- ADMIN: EXAMS ----------

@app.post("/admin/exams", status_code=201)
def create_exam(data: ExamIn, user=Depends(admin_only), db=Depends(get_db)):
    cur = db.execute("""
        INSERT INTO exams(title,description,status,created_by,created_at)
        VALUES(?,?,'draft',?,?)
    """, (data.title, data.description, user["id"], now()))
    db.commit()
    return {"id": cur.lastrowid, "title": data.title, "status": "draft"}


@app.patch("/admin/exams/{exam_id}")
def update_exam(
    exam_id: int, data: ExamIn,
    user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    db.execute(
        "UPDATE exams SET title=?,description=? WHERE id=?",
        (data.title, data.description, exam_id)
    )
    db.commit()
    return {"message": "Draft test yangilandi", "exam_id": exam_id}


@app.delete("/admin/exams/{exam_id}")
def delete_exam(
    exam_id: int, user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    db.execute("DELETE FROM exams WHERE id=?", (exam_id,))
    db.commit()
    return {"message": "Draft test o'chirildi", "exam_id": exam_id}


# ---------- ADMIN: QUESTIONS AND CHOICES ----------

@app.get("/admin/exams/{exam_id}/questions")
def admin_questions(
    exam_id: int, user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    questions = db.execute(
        "SELECT * FROM questions WHERE exam_id=? ORDER BY position,id",
        (exam_id,)
    ).fetchall()
    result = []
    for q in questions:
        choices = db.execute(
            "SELECT id,text,is_correct FROM choices WHERE question_id=? ORDER BY id",
            (q["id"],)
        ).fetchall()
        result.append({
            "id": q["id"], "text": q["text"],
            "choices": [dict(c) for c in choices],
        })
    return result


@app.post("/admin/exams/{exam_id}/questions", status_code=201)
def add_question(
    exam_id: int, data: QuestionIn,
    user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    position = db.execute(
        "SELECT COUNT(*) FROM questions WHERE exam_id=?", (exam_id,)
    ).fetchone()[0] + 1
    cur = db.execute(
        "INSERT INTO questions(exam_id,text,position) VALUES(?,?,?)",
        (exam_id, data.text, position)
    )
    qid = cur.lastrowid
    db.executemany(
        "INSERT INTO choices(question_id,text,is_correct) VALUES(?,?,?)",
        [(qid, c.text, int(c.is_correct)) for c in data.choices]
    )
    db.commit()
    return {"message": "Savol qo'shildi", "question_id": qid}


@app.patch("/admin/exams/{exam_id}/questions/{question_id}")
def update_question(
    exam_id: int, question_id: int, data: QuestionIn,
    user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    get_question(db, exam_id, question_id)
    db.execute(
        "UPDATE questions SET text=? WHERE id=?",
        (data.text, question_id)
    )
    db.execute("DELETE FROM choices WHERE question_id=?", (question_id,))
    db.executemany(
        "INSERT INTO choices(question_id,text,is_correct) VALUES(?,?,?)",
        [(question_id, c.text, int(c.is_correct)) for c in data.choices]
    )
    db.commit()
    return {"message": "Savol yangilandi", "question_id": question_id}


@app.delete("/admin/exams/{exam_id}/questions/{question_id}")
def delete_question(
    exam_id: int, question_id: int,
    user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    get_question(db, exam_id, question_id)
    db.execute("DELETE FROM choices WHERE question_id=?", (question_id,))
    db.execute("DELETE FROM questions WHERE id=?", (question_id,))
    db.commit()
    return {"message": "Savol o'chirildi", "question_id": question_id}


@app.post("/admin/exams/{exam_id}/publish")
def publish_exam(
    exam_id: int, user=Depends(admin_only), db=Depends(get_db)
):
    get_draft_exam(db, exam_id)
    questions = db.execute(
        "SELECT * FROM questions WHERE exam_id=?", (exam_id,)
    ).fetchall()
    if not questions:
        raise HTTPException(status_code=400, detail="Bo'sh testni e'lon qilib bo'lmaydi")

    for q in questions:
        choices = db.execute(
            "SELECT is_correct FROM choices WHERE question_id=?",
            (q["id"],)
        ).fetchall()
        if len(choices) != 4 or sum(c["is_correct"] for c in choices) != 1:
            raise HTTPException(
                status_code=400,
                detail="Har savolda 4 variant va 1 to'g'ri javob bo'lishi shart"
            )

    db.execute("UPDATE exams SET status='published' WHERE id=?", (exam_id,))
    db.commit()
    return {"message": "Test e'lon qilindi", "exam_id": exam_id}


# ---------- PUBLISHED EXAMS ----------

@app.get("/exams")
def list_exams(db=Depends(get_db)):
    rows = db.execute("""
        SELECT e.id,e.title,e.description,e.created_at,COUNT(q.id) AS question_count
        FROM exams e LEFT JOIN questions q ON q.exam_id=e.id
        WHERE e.status='published'
        GROUP BY e.id ORDER BY e.id DESC
    """).fetchall()
    return [dict(r) for r in rows]


@app.get("/exams/{exam_id}")
def exam_detail(exam_id: int, db=Depends(get_db)):
    exam = db.execute(
        "SELECT * FROM exams WHERE id=? AND status='published'", (exam_id,)
    ).fetchone()
    if not exam:
        raise HTTPException(status_code=404, detail="E'lon qilingan test topilmadi")
    questions = db.execute(
        "SELECT * FROM questions WHERE exam_id=? ORDER BY position,id",
        (exam_id,)
    ).fetchall()
    return {
        "id": exam["id"], "title": exam["title"],
        "description": exam["description"],
        "questions": [public_question(db, q) for q in questions],
    }


# ---------- STUDENT ATTEMPTS ----------

@app.post("/exams/{exam_id}/attempts", status_code=201)
def start_attempt(
    exam_id: int, user=Depends(current_user), db=Depends(get_db)
):
    if user["role"] != "student":
        raise HTTPException(status_code=403, detail="Faqat student test topshiradi")
    exam = db.execute(
        "SELECT id FROM exams WHERE id=? AND status='published'", (exam_id,)
    ).fetchone()
    if not exam:
        raise HTTPException(status_code=404, detail="Test topilmadi yoki e'lon qilinmagan")
    previous = db.execute(
        "SELECT id FROM attempts WHERE user_id=? AND exam_id=?",
        (user["id"], exam_id)
    ).fetchone()
    if previous:
        raise HTTPException(status_code=409, detail="Bu test uchun urinish allaqachon boshlangan")

    cur = db.execute(
        "INSERT INTO attempts(user_id,exam_id,started_at) VALUES(?,?,?)",
        (user["id"], exam_id, now())
    )
    db.commit()
    return {"attempt_id": cur.lastrowid, "exam_id": exam_id, "status": "active"}


@app.get("/attempts/{attempt_id}/questions")
def attempt_questions(
    attempt_id: int, user=Depends(current_user), db=Depends(get_db)
):
    attempt = get_attempt(db, attempt_id, user["id"])
    if attempt["completed_at"]:
        raise HTTPException(status_code=409, detail="Urinish tugatilgan")
    qs = db.execute(
        "SELECT * FROM questions WHERE exam_id=? ORDER BY position,id",
        (attempt["exam_id"],)
    ).fetchall()
    return [public_question(db, q) for q in qs]


@app.put("/attempts/{attempt_id}/answers")
def save_answer(
    attempt_id: int, data: AnswerIn,
    user=Depends(current_user), db=Depends(get_db)
):
    attempt = get_attempt(db, attempt_id, user["id"])
    if attempt["completed_at"]:
        raise HTTPException(status_code=409, detail="Tugatilgan test javobi o'zgartirilmaydi")

    question = db.execute(
        "SELECT id FROM questions WHERE id=? AND exam_id=?",
        (data.question_id, attempt["exam_id"])
    ).fetchone()
    if not question:
        raise HTTPException(status_code=400, detail="Savol ushbu testga tegishli emas")

    choice = db.execute(
        "SELECT id FROM choices WHERE id=? AND question_id=?",
        (data.choice_id, data.question_id)
    ).fetchone()
    if not choice:
        raise HTTPException(status_code=400, detail="Variant ushbu savolga tegishli emas")

    previous = db.execute(
        "SELECT id FROM answers WHERE attempt_id=? AND question_id=?",
        (attempt_id, data.question_id)
    ).fetchone()

    if previous:
        db.execute(
            "UPDATE answers SET choice_id=? WHERE id=?",
            (data.choice_id, previous["id"])
        )
        message = "Javob almashtirildi"
    else:
        db.execute(
            "INSERT INTO answers(attempt_id,question_id,choice_id) VALUES(?,?,?)",
            (attempt_id, data.question_id, data.choice_id)
        )
        message = "Javob saqlandi"
    db.commit()
    return {"message": message, "question_id": data.question_id}


@app.post("/attempts/{attempt_id}/finish")
def finish_attempt(
    attempt_id: int, user=Depends(current_user), db=Depends(get_db)
):
    attempt = get_attempt(db, attempt_id, user["id"])
    if attempt["completed_at"]:
        raise HTTPException(status_code=409, detail="Urinish avval tugatilgan")

    total = db.execute(
        "SELECT COUNT(*) FROM questions WHERE exam_id=?",
        (attempt["exam_id"],)
    ).fetchone()[0]
    if total == 0:
        raise HTTPException(status_code=400, detail="Testda savollar yo'q")

    correct = db.execute("""
        SELECT COUNT(*)
        FROM answers a
        JOIN questions q ON q.id=a.question_id
        JOIN choices c ON c.id=a.choice_id AND c.question_id=q.id
        WHERE a.attempt_id=? AND q.exam_id=? AND c.is_correct=1
    """, (attempt_id, attempt["exam_id"])).fetchone()[0]

    percent = round(correct / total * 100, 2)
    finished = now()
    db.execute("""
        UPDATE attempts SET completed_at=?,correct_count=?,
            total_questions=?,percent=?
        WHERE id=? AND user_id=? AND completed_at IS NULL
    """, (finished, correct, total, percent, attempt_id, user["id"]))
    db.commit()
    return {
        "message": "Test yakunlandi",
        "attempt_id": attempt_id,
        "correct_answers": correct,
        "total_questions": total,
        "percent": percent,
        "completed_at": finished,
    }


# ---------- RESULTS ----------

def format_result(row):
    return {
        "attempt_id": row["id"],
        "exam_id": row["exam_id"],
        "exam_title": row["exam_title"],
        "student_id": row["user_id"],
        "student_name": row["full_name"],
        "correct_answers": row["correct_count"],
        "total_questions": row["total_questions"],
        "percent": row["percent"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
    }


@app.get("/me/results")
def my_results(user=Depends(current_user), db=Depends(get_db)):
    rows = db.execute("""
        SELECT a.*,e.title AS exam_title,u.full_name
        FROM attempts a
        JOIN exams e ON e.id=a.exam_id
        JOIN users u ON u.id=a.user_id
        WHERE a.user_id=? AND a.completed_at IS NOT NULL
        ORDER BY a.completed_at DESC
    """, (user["id"],)).fetchall()
    return [format_result(r) for r in rows]


@app.get("/admin/exams/{exam_id}/results")
def admin_results(
    exam_id: int, user=Depends(admin_only), db=Depends(get_db)
):
    get_exam(db, exam_id)
    rows = db.execute("""
        SELECT a.*,e.title AS exam_title,u.full_name
        FROM attempts a
        JOIN exams e ON e.id=a.exam_id
        JOIN users u ON u.id=a.user_id
        WHERE a.exam_id=? AND a.completed_at IS NOT NULL
        ORDER BY a.percent DESC,a.completed_at ASC
    """, (exam_id,)).fetchall()
    return [format_result(r) for r in rows]
