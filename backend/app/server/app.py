from fastapi import FastAPI
from app.server.routes.findings_route import router as FindingRouter
from app.server.routes.user_route import router as UserRouter
from app.server.routes.login_route import router as LoginRouter
from app.server.routes.misc import router as MiscRouter
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(FindingRouter, tags=["Finding"], prefix='/finding')
app.include_router(UserRouter, tags=["User"], prefix='/user')
app.include_router(LoginRouter, tags=['Login', 'GetAccessToken'], prefix='/token')
app.include_router(MiscRouter, tags=['Miscellaneous'], prefix='/misc')

@app.get("/", tags=['root'])
async def root():
    return {"message": "Hello World"}
