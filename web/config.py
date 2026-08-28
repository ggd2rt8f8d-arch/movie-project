import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY", "очень-длинный-секретный-ключ-минимум-32-символа")
ADMIN_TELEGRAM_IDS = [
    int(x.strip()) for x in os.getenv("ADMIN_TELEGRAM_IDS", "").split(",") if x.strip().isdigit()
]

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
