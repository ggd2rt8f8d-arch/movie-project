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

def generate_code_verifier():
    return secrets.token_urlsafe(64)

def generate_code_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

@router.get("/google")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    code_verifier = generate_code_verifier()
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
    state_raw = request.query_params.get("state")
    code_verifier = None
    if state_raw:
        try:
            state_data = json.loads(unquote(state_raw))
            code_verifier = state_data.get("cv")
        except:
            code_verifier = None

    if not code_verifier:
        code_verifier = request.session.get("code_verifier")
    
    if not code_verifier:
        raise HTTPException(400, "Ошибка: Не найден code_verifier")

    try:
        token = await oauth.google.authorize_access_token(request, code_verifier=code_verifier)
    except Exception as e:
        raise HTTPException(500, f"Ошибка обмена токена: {str(e)}")
        
    info = token.get("userinfo")
    
    if not info:
        raise HTTPException(400, "Ошибка Google: не удалось получить данные пользователя")

    pool = await get_pool()
    async with pool.connection() as conn:
        # Используем методы psycopg: fetchone вместо fetchrow
        user = await (await conn.execute("SELECT * FROM users WHERE google_id = %s", (info["sub"],))).fetchone()
        
        if not user:
            # INSERT ... RETURNING * -> fetchone
            user = await (await conn.execute("""
                INSERT INTO users (google_id, email, full_name, avatar_url)
                VALUES (%s, %s, %s, %s)
                RETURNING *
            """, (info["sub"], info.get("email"), info.get("name"), info.get("picture")))).fetchone()
        else:
            await conn.execute("""
                UPDATE users SET email=%s, full_name=%s, avatar_url=%s WHERE id=%s
            """, (info.get("email"), info.get("name"), info.get("picture"), user["id"]))
            user = await (await conn.execute("SELECT * FROM users WHERE id = %s", (user["id"],))).fetchone()

    # Так как psycopg возвращает Record (а не dict), проверьте доступ по ключам или индексам.
    # Обычно user["id"] работает, но если нет, используйте user[0]
    request.session["user"] = {
        "id": user["id"] if "id" in user.keys() else user[0], 
        "full_name": user["full_name"] if "full_name" in user.keys() else user[2],
        "avatar_url": user["avatar_url"] if "avatar_url" in user.keys() else user[3],
        "is_admin": user["is_admin"] if "is_admin" in user.keys() else user[4],
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
        # Проверяем старую таблицу (fetchone)
        admin_check = await (await conn.execute("SELECT 1 FROM admins WHERE user_id = %s", (tg_id,))).fetchone()
        if admin_check:
            is_admin = True

        user = await (await conn.execute("SELECT * FROM users WHERE telegram_id = %s", (tg_id,))).fetchone()
        if not user:
            user = await (await conn.execute("""
                INSERT INTO users (telegram_id, full_name, avatar_url, is_admin)
                VALUES (%s, %s, %s, %s)
                RETURNING *
            """, (tg_id, full_name, avatar, is_admin))).fetchone()
        else:
            await conn.execute("""
                UPDATE users SET full_name=%s, avatar_url=%s, is_admin = is_admin OR %s
                WHERE telegram_id=%s
            """, (full_name, avatar, is_admin, tg_id))
            user = await (await conn.execute("SELECT * FROM users WHERE telegram_id = %s", (tg_id,))).fetchone()

    request.session["user"] = {
        "id": user["id"] if "id" in user.keys() else user[0],
        "full_name": user["full_name"] if "full_name" in user.keys() else user[2],
        "avatar_url": user["avatar_url"] if "avatar_url" in user.keys() else user[3],
        "is_admin": user["is_admin"] if "is_admin" in user.keys() else user[4],
        "provider": "telegram"
    }
    return RedirectResponse("/", status_code=303)

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
