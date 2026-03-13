from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware # IMPORTANTE
from app.routes.events import router as events_router
from app.database import init_db

app = FastAPI(title="Security Coach API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]  # PARA PERMITIR DESCARGA DE ARCHIVOS
)
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class PrivateNetworkMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # ESTO ES LO QUE PIDE CHROME:
        response.headers["Access-Control-Allow-Private-Network"] = "true"
        return response

app.add_middleware(PrivateNetworkMiddleware)

@app.middleware("http")
async def add_pna_header(request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response

app.include_router(events_router) 

@app.on_event("startup")
def startup():
    init_db()
