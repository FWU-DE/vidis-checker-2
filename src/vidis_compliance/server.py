from fastapi import FastAPI
from .cli import load_criteria

app = FastAPI(title="VIDIS Compliance API")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/criteria")
def criteria():
    crit = load_criteria()
    return {"items": {k: v.model_dump() for k, v in crit.items.items()}}
