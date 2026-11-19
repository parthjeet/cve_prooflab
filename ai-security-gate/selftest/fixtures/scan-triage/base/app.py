"""Small user lookup service."""
import db

DEFAULT_LIMIT = 20


def show_user(name):
    rows = db.find_user(name)
    return rows[: DEFAULT_LIMIT]


def show_orders(user_id):
    return db.list_orders(user_id)
