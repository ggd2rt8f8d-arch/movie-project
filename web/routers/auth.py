import hashlib
import hmac
import time

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


@router.get("/google")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    info = token.get("userinfo")
    if not info:
        raise HTTPException(400, "Ошибка Google")

    pool = await get_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE google_id = $1", info["sub"])
        if not user:
            user = await conn.fetchrow("""
                INSERT INTO users (google_id, email, full_name, avatar_url)
                VALUES ($1, $2, $3, $4) RETURNING *
            """, info["sub"], info.get("email"), info.get("name"), info.get("picture"))
        else:
            await conn.execute("""
                UPDATE users SET email=$1, full_name=$2, avatar_url=$3 WHERE id=$4
            """, info.get("email"), info.get("name"), info.get("picture"), user["id"])
            user = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user["id"])

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
    async with pool.acquire() as conn:
        # Подтягиваем админку из старой таблицы бота
        if await conn.fetchval("SELECT 1 FROM admins WHERE user_id = $1", tg_id):
            is_admin = True

        user = await conn.fetchrow("SELECT * FROM users WHERE telegram_id = $1", tg_id)
        if not user:
            user = await conn.fetchrow("""
                INSERT INTO users (telegram_id, full_name, avatar_url, is_admin)
                VALUES ($1, $2, $3, $4) RETURNING *
            """, tg_id, full_name, avatar, is_admin)
        else:
            await conn.execute("""
                UPDATE users SET full_name=$1, avatar_url=$2, is_admin = is_admin OR $3
                WHERE telegram_id=$4
            """, full_name, avatar, is_admin, tg_id)
            user = await conn.fetchrow("SELECT * FROM users WHERE telegram_id = $1", tg_id)

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
