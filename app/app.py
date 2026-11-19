import sqlite3

from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


class Status(HTTPEndpoint):
    async def get(self, request):
        return PlainTextResponse("OK")

    async def diagnostics(self, request):
        return PlainTextResponse("diagnostics: ok")


async def version(request):
    return PlainTextResponse("1.0.0")


_notes_db = sqlite3.connect(":memory:", check_same_thread=False)
_notes_db.execute("CREATE TABLE notes (owner TEXT, body TEXT)")
_notes_db.executemany(
    "INSERT INTO notes (owner, body) VALUES (?, ?)",
    [
        ("alice", "Buy milk"),
        ("bob", "Call home"),
        ("alice", "Book flights"),
    ],
)
_notes_db.commit()


async def notes(request):
    owner = request.query_params.get("owner", "")
    query = f"SELECT body FROM notes WHERE owner = '{owner}'"
    cursor = _notes_db.cursor()
    cursor.execute(query)
    bodies = [row[0] for row in cursor.fetchall()]
    return PlainTextResponse("\n".join(bodies))


app = Starlette(
    routes=[
        Mount("/static", app=StaticFiles(directory="static"), name="static"),
        Route("/status", Status),
        Route("/version", version, methods=["GET"]),
        Route("/notes", notes, methods=["GET"]),
    ]
)
