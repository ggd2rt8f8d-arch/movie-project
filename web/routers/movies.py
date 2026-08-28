from fastapi import APIRouter, Request, HTTPException
from fastapi.templating import Jinja2Templates

from database import get_pool

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/movie/{code}")
async def movie_page(request: Request, code: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        movie = await conn.fetchrow("SELECT * FROM movies WHERE code = $1", code)

    if not movie:
        raise HTTPException(status_code=404, detail="Фильм не найден")

    user = request.session.get("user")
    return templates.TemplateResponse("movie.html", {
        "request": request,
        "movie": dict(movie),
        "user": user,
        "is_admin": bool(user and user.get("is_admin"))
    })
