from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


async def status(request):
    return PlainTextResponse("OK")


app = Starlette(
    routes=[
        Mount("/static", app=StaticFiles(directory="static"), name="static"),
        Route("/status", status, methods=["GET"]),
    ]
)
