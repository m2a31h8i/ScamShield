from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import requests

app = FastAPI()

templates = Jinja2Templates(directory="templates")

TEXT_API = "http://localhost:8001/analyze-text"
QR_API = "http://localhost:8002/scan-qr"


@app.get("/my-tools", response_class=HTMLResponse)
def open_dashboard(request: Request):
    return templates.TemplateResponse("my_dashboard.html", {"request": request})