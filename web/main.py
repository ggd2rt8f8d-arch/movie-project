import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from config import SECRET_KEY
from database import init_db
from routers import main, movies, auth, admin

app = FastAPI(title="Movie Site")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=60 * 60 * 24 * 30)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(main.router)
app.include_router(movies.router)
app.include_router(auth.router)
app.include_router(admin.router)


@app.on_event("startup")
async def on_startup():
    await init_db()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
