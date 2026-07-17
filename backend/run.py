"""
Entry point - `python -m backend.run`.

Binds to 127.0.0.1 only (local-first) and sets the Windows event-loop policy
that subprocess streaming needs. Uses the `wsproto` WebSocket backend, which
is decoupled from the `websockets` package version.
"""
import asyncio
import sys

import uvicorn

from .config import settings

if sys.platform == "win32":
    # Proactor loop is needed for subprocess streaming on Windows. The policy API
    # is deprecated in newer Python but still works; silence the noise.
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass


def main():
    uvicorn.run("backend.api.app:app", host=settings.HOST, port=settings.PORT,
                reload=False, ws="wsproto")


if __name__ == "__main__":
    main()
