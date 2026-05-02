import uvicorn

from harp.config import settings


def main():
    uvicorn.run(
        "harp.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=settings.reload,
    )


if __name__ == "__main__":
    main()
