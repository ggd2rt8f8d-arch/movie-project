import asyncpg
from config import DATABASE_URL

pool = None

async def init_db():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL)

    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                telegram_id BIGINT UNIQUE,
                google_id TEXT UNIQUE,
                email TEXT,
                full_name TEXT,
                avatar_url TEXT,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS movies (
                code TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                year INTEGER,
                poster TEXT,
                description TEXT,
                rating TEXT
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                user_id BIGINT PRIMARY KEY
            )
        """)

async def get_pool():
    return pool
