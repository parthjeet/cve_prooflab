"""Database helpers backed by sqlite3."""
import sqlite3

DB_PATH = "shop.db"
ORDERS_TABLE = "orders"


def connect():
    return sqlite3.connect(DB_PATH)


def find_user(name):
    """Look up users by a name taken from the request."""
    conn = connect()
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def list_orders(user_id):
    """Return the orders of one user."""
    conn = connect()
    query = f"SELECT id, total FROM {ORDERS_TABLE} WHERE user_id = ?"
    rows = conn.execute(query, (user_id,)).fetchall()
    conn.close()
    return rows
