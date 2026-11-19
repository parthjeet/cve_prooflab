from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles


async def status(request):
    return PlainTextResponse("OK")


async def version(request):
    return PlainTextResponse("1.0.0")


app = Starlette(
    routes=[
        Mount("/static", app=StaticFiles(directory="static"), name="static"),
        Route("/status", status, methods=["GET"]),
        Route("/version", version, methods=["GET"]),
    ]
)
