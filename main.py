import uvicorn

from dnsctl.config import settings


def main():
    uvicorn.run(
        "dnsctl.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=settings.reload,
    )


if __name__ == "__main__":
    main()
