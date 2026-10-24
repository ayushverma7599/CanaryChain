from fastapi import FastAPI

from app.api.routes.core import router as core_router

app = FastAPI(title="CanaryChain Core API", version="0.1.0")
app.include_router(core_router)