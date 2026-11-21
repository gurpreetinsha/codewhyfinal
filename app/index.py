"""Vercel FastAPI entry point.

Vercel discovers ASGI applications exported as app from app/index.py.
Keep the application implementation in app.main so local Uvicorn and Docker
continue to use the same instance.
"""
from app.main import app

__all__ = ["app"]
