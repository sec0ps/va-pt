"""Password hashing, session helpers, and access-control decorators."""

from functools import wraps

from flask import session, redirect, url_for, flash, g
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

import db

_ph = PasswordHasher()


def hash_password(password):
    return _ph.hash(password)


def verify_password(password_hash, password):
    try:
        _ph.verify(password_hash, password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False
    except Exception:
        return False


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = db.get_user(user_id)
    if user is None or not user["active"]:
        return None
    return user


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("ui.login"))
        g.user = user
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("ui.login"))
        if user["role"] != "admin":
            flash("admin access required", "error")
            return redirect(url_for("ui.dashboard"))
        g.user = user
        return view(*args, **kwargs)
    return wrapper


def can_access_workspace(user, workspace_id):
    if user["role"] == "admin":
        return True
    return db.user_has_workspace(user["id"], workspace_id)
