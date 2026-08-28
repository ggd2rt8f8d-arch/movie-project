import hashlib
import hmac
import time
import secrets
import base64
import json
from urllib.parse import quote, unquote

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse

from config import (
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
    BOT_TOKEN, BASE_URL, ADMIN_TELEGRAM_IDS
)
from database import get_pool

router = APIRouter(prefix="/auth")

oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# Функция для генерации code_verifier (стандарт PKCE)
def generate_code_verifier():
    return secrets.token_urlsafe(64)

# Функция для генерации code_challenge из code_verifier
def generate_code_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


@router.get("/google")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    
    # Генерируем code_verifier
    code_verifier = generate_code_verifier()
    
    # Сохраняем его В URL внутри параметра state (это надежно работает с куками)
    state = quote(json.dumps({"cv": code_verifier}))
    
    code_challenge = generate_code_challenge(code_verifier)
    
    return await oauth.google.authorize_redirect(
        request, 
        redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method="S256"
    )


@router.get("/google/callback")
async def google_callback(request: Request):
    # 1. Достаем code_verifier из параметра state, который вернулся от Google
    state_raw = request.query_params.get("state")
    code_verifier = None
    if state_raw:
        try:
            state_data = json.loads(unquote(state_raw))
            code_verifier = state_data.get("cv")
        except:
            code_verifier = None

    # Если вдруг сессия сохранилась, берем оттуда, иначе берем из state
    if not code_verifier:
        code_verifier = request.session.get("code_verifier")
    
    if not code_verifier:
        raise HTTPException(400, "Ошибка: Не найден code_verifier")

    # 2. Передаем его явно в запрос к Google
    try:
        token = await oauth.google.authorize_access_token(request, code_verifier=code_verifier)
    except Exception as e:
        # Если ошибка, выводим её в логи, чтобы вы видели причину
        raise HTTPException(500, f"Ошибка обмена токена: {str(e)}")
        
    info = token.get("userinfo")
    
    if not info:
        raise HTTPException(400, "Ошибка Google: не удалось получить данные пользователя")

    pool = await get_pool()
    async with pool.connection() as conn:
        # Проверяем, существует ли пользователь
        user = await conn.fetchrow("SELECT * FROM users WHERE google_id = %s", (info["sub"],))
        
        if not user:
            user = await conn.fetchrow("""
                INSERT INTO users (google_id, email, full_name, avatar_url)
                VALUES (%s, %s, %s, %s)
                RETURNING *
            """, (info["sub"], info.get("email"), info.get("name"), info.get("picture")))
        else:
            await conn.execute("""
                UPDATE users SET email=%s, full_name=%s, avatar_url=%s WHERE id=%s
            """, (info.get("email"), info.get("name"), info.get("picture"), user["id"]))
            user = await conn.fetchrow("SELECT * FROM users WHERE id = %s", (user["id"],))

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
    data = dict(request.query_params)
    check_hash = data.pop("hash", None)
    if not check_hash:
        raise HTTPException(400, "Нет hash")

    data_check = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    if hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest() != check_hash:
        raise HTTPException(403, "Подпись неверна")

    if time.time() - int(data.get("auth_date", 0)) > 86400:
        raise HTTPException(403, "Данные устарели")

    tg_id = int(data["id"])
    full_name = f"{data.get('first_name', '')} {data.get('last_name', '')}".strip()
    avatar = data.get("photo_url")

    is_admin = tg_id in ADMIN_TELEGRAM_IDS

    pool = await get_pool()
    async with pool.connection() as conn:
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
