"""Small user store backed by sqlite3."""
import sqlite3

DB_PATH = "users.db"


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
    )
    return conn


def add_user(name, email):
    conn = connect()
    with conn:
        conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    conn.close()


def list_users():
    conn = connect()
    rows = conn.execute("SELECT id, name, email FROM users ORDER BY id").fetchall()
    conn.close()
    return rows


def find_user(name):
    """Look up users by a name taken from the request."""
    conn = connect()
    query = "SELECT id, name, email FROM users WHERE name = '" + name + "'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows
