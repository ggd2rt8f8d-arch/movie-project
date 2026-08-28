from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from database import get_pool

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": request.session.get("user")
    })


@router.post("/search")
async def search(request: Request, code: str = Form(...)):
    code = code.strip()
    pool = await get_pool()

    async with pool.connection() as conn:
        exists = await conn.fetchval("SELECT 1 FROM movies WHERE code = %s", (code,))

    if exists:
        return RedirectResponse(f"/movie/{code}", status_code=303)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": request.session.get("user"),
        "error": "Фильм с таким кодом не найден"
    })
