from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from database import get_pool

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")


def require_admin(request: Request):
    user = request.session.get("user")
    if not user or not user.get("is_admin"):
        raise HTTPException(403, "Нет доступа")
    return user


@router.get("/")
async def admin_home(request: Request):
    require_admin(request)
    pool = await get_pool()
    async with pool.acquire() as conn:
        movies = await conn.fetch("SELECT code, title, year FROM movies ORDER BY code")
    return templates.TemplateResponse("admin/index.html", {
        "request": request,
        "user": request.session.get("user"),
        "movies": movies
    })


@router.get("/add")
async def add_form(request: Request):
    require_admin(request)
    return templates.TemplateResponse("admin/add.html", {
        "request": request,
        "user": request.session.get("user")
    })


@router.post("/add")
async def add_movie(
    request: Request,
    code: str = Form(...),
    title: str = Form(...),
    year: int = Form(...),
    poster: str = Form(...),
    description: str = Form(...),
    rating: str = Form(...)
):
    require_admin(request)
    pool = await get_pool()
    async with pool.acquire() as conn:
        try:
            await conn.execute("""
                INSERT INTO movies (code, title, year, poster, description, rating)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, code.strip(), title.strip(), year, poster.strip(), description.strip(), rating.strip())
        except Exception:
            return templates.TemplateResponse("admin/add.html", {
                "request": request,
                "user": request.session.get("user"),
                "error": "Такой код уже существует"
            })
    return RedirectResponse("/admin/", status_code=303)


@router.get("/edit/{code}")
async def edit_form(request: Request, code: str):
    require_admin(request)
    pool = await get_pool()
    async with pool.acquire() as conn:
        movie = await conn.fetchrow("SELECT * FROM movies WHERE code = $1", code)
    if not movie:
        raise HTTPException(404)
    return templates.TemplateResponse("admin/edit.html", {
        "request": request,
        "user": request.session.get("user"),
        "movie": dict(movie)
    })


@router.post("/edit/{code}")
async def edit_movie(
    request: Request,
    code: str,
    title: str = Form(...),
    year: int = Form(...),
    poster: str = Form(...),
    description: str = Form(...),
    rating: str = Form(...)
):
    require_admin(request)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE movies SET title=$1, year=$2, poster=$3, description=$4, rating=$5
            WHERE code=$6
        """, title.strip(), year, poster.strip(), description.strip(), rating.strip(), code)
    return RedirectResponse(f"/movie/{code}", status_code=303)


@router.post("/delete/{code}")
async def delete_movie(request: Request, code: str):
    require_admin(request)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM movies WHERE code = $1", code)
    return RedirectResponse("/admin/", status_code=303)
