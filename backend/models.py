# backend/models.py
import time
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Nonce(db.Model):
    __tablename__ = "nonces"
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(128), unique=True, nullable=False)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    used = db.Column(db.Boolean, default=False)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(42), unique=True, nullable=False)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
