from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


# This route is deliberate. It meets the precondition of CVE-2026-48817: an
# HTTPEndpoint subclass routed without methods=, with an extra method named like
# a non-standard HTTP verb. It returns fixed text. It exists as a target for a
# showcase task.
class Status(HTTPEndpoint):
    async def get(self, request):
        return PlainTextResponse("OK")

    async def diagnostics(self, request):
        return PlainTextResponse("LAB-MARKER-DIAGNOSTICS")


app = Starlette(
    routes=[
        Mount("/static", app=StaticFiles(directory="static"), name="static"),
        Route("/status", Status),
    ]
)
