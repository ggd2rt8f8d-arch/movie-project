import uvicorn
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from config import SECRET_KEY
from database import init_db
from routers import main, movies, auth, admin

app = FastAPI(title="Movie Site")

# ===== ИЗМЕНЕНИЕ №1: Настройка сессий для работы с HTTPS =====
# Берем секретный ключ из переменных окружения (если он есть), иначе используем из config
# https_only=True заставляет браузер хранить куки только на HTTPS (обязательно для Railway)
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SESSION_SECRET", SECRET_KEY), 
    max_age=60 * 60 * 24 * 30,  # 30 дней
    https_only=True,  # <--- ГЛАВНОЕ ИЗМЕНЕНИЕ
    same_site="lax"   # <--- Безопасность для OAuth
)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(main.router)
app.include_router(movies.router)
app.include_router(auth.router)
app.include_router(admin.router)


@app.on_event("startup")
async def on_startup():
    await init_db()


if __name__ == "__main__":
    # ВАЖНО: При запуске на Railway не используйте reload=True, это ломает продакшен
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
