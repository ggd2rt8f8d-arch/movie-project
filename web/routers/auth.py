import hashlib
import hmac
import time
import secrets

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse

from config import (
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
    BOT_TOKEN, BASE_URL, ADMIN_TELEGRAM_IDS
)
from database import get_pool

router = APIRouter(prefix="/auth")

# Инициализация OAuth
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@router.get("/google")
async def google_login(request: Request):
    """
    Эта функция теперь генерирует PKCE (code_verifier и code_challenge).
    Это строгое требование Google для безопасности OAuth 2.0.
    """
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    
    # Генерируем случайный code_verifier для PKCE
    code_verifier = secrets.token_urlsafe(64)  # Длина 86 символов (в пределах 43-128)
    
    # Сохраняем его в сессии, чтобы проверить при колбэке
    request.session["code_verifier"] = code_verifier
    
    # Передаем challenge в запрос
    return await oauth.google.authorize_redirect(
        request, 
        redirect_uri,
        code_challenge=oauth.google.create_code_challenge(code_verifier),
        code_challenge_method="S256"
    )


@router.get("/google/callback")
async def google_callback(request: Request):
    # Получаем токен (Authlib сам подставит code_verifier из вашей сессии, если вы используете Starlette)
    token = await oauth.google.authorize_access_token(request)
    info = token.get("userinfo")
    
    if not info:
        raise HTTPException(400, "Ошибка Google: не удалось получить данные пользователя")

    # Проверяем, что email подтвержден (иногда Google отдает пустой email)
    if not info.get("email"):
        raise HTTPException(400, "Google не предоставил email. Проверьте настройки OAuth")

    pool = await get_pool()
    async with pool.connection() as conn:
        # Проверяем, существует ли пользователь
        user = await conn.fetchrow("SELECT * FROM users WHERE google_id = %s", (info["sub"],))
        
        if not user:
            # Создаем нового пользователя
            user = await conn.fetchrow("""
                INSERT INTO users (google_id, email, full_name, avatar_url)
                VALUES (%s, %s, %s, %s)
                RETURNING *
            """, (info["sub"], info.get("email"), info.get("name"), info.get("picture")))
        else:
            # Обновляем данные существующего
            await conn.execute("""
                UPDATE users SET email=%s, full_name=%s, avatar_url=%s WHERE id=%s
            """, (info.get("email"), info.get("name"), info.get("picture"), user["id"]))
            user = await conn.fetchrow("SELECT * FROM users WHERE id = %s", (user["id"],))

    # Записываем данные в сессию
    request.session["user"] = {
        "id": user["id"],
        "full_name": user["full_name"],
        "avatar_url": user["avatar_url"],
        "is_admin": user["is_admin"],
        "provider": "google"
    }
    return RedirectResponse("/", status_code=303)


@router.get("/telegram/callback")
async def telegram_callback(request: Request):
    # Получаем все параметры из URL
    data = dict(request.query_params)
    
    # Хеш должен быть в конце, убираем его из данных
    check_hash = data.pop("hash", None)
    if not check_hash:
        raise HTTPException(400, "Нет hash")

    # Сортируем ключи и создаем строку для проверки (строго по документации Telegram)
    data_check = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    
    # Вычисляем секретный ключ
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    
    # Сравниваем подписи
    if hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest() != check_hash:
        raise HTTPException(403, "Подпись неверна")

    # Проверяем актуальность данных (не старше 24 часов)
    if time.time() - int(data.get("auth_date", 0)) > 86400:
        raise HTTPException(403, "Данные устарели")

    tg_id = int(data["id"])
    full_name = f"{data.get('first_name', '')} {data.get('last_name', '')}".strip()
    avatar = data.get("photo_url")

    # Проверяем, является ли пользователь админом
    is_admin = tg_id in ADMIN_TELEGRAM_IDS

    pool = await get_pool()
    async with pool.connection() as conn:
        # Проверяем старую таблицу админов бота (если она есть)
        if await conn.fetchval("SELECT 1 FROM admins WHERE user_id = %s", (tg_id,)):
            is_admin = True

        user = await conn.fetchrow("SELECT * FROM users WHERE telegram_id = %s", (tg_id,))
        if not user:
            user = await conn.fetchrow("""
                INSERT INTO users (telegram_id, full_name, avatar_url, is_admin)
                VALUES (%s, %s, %s, %s)
                RETURNING *
            """, (tg_id, full_name, avatar, is_admin))
        else:
            await conn.execute("""
                UPDATE users SET full_name=%s, avatar_url=%s, is_admin = is_admin OR %s
                WHERE telegram_id=%s
            """, (full_name, avatar, is_admin, tg_id))
            user = await conn.fetchrow("SELECT * FROM users WHERE telegram_id = %s", (tg_id,))

    request.session["user"] = {
        "id": user["id"],
        "full_name": user["full_name"],
        "avatar_url": user["avatar_url"],
        "is_admin": user["is_admin"],
        "provider": "telegram"
    }
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
