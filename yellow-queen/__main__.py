from yellow_queen.config import HOST, PORT


def main() -> None:
    import uvicorn
    print(f"[yellow-queen] Start auf http://{HOST}:{PORT}  (YQ_HOST / YQ_PORT ändern)")
    uvicorn.run("yellow_queen.web.app:app", host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
