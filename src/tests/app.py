import os

DB_PASSWORD = "super_secret_password_123"

API_KEY = "AIzaSyB1234567890abcdefghijklmnopqrstuv"

def connect_database():
    conn_str = "postgresql://admin:password123@localhost:5432/mydb"
    return conn_str

def get_headers():
    return {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake_token"
    }

DB_PASSWORD_SAFE = os.environ.get("DB_PASSWORD")