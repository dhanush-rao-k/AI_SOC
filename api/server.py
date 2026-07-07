from __future__ import annotations

from .routes import analyze_log, health_check


def create_server() -> dict[str, object]:
    return {"health_check": health_check, "analyze_log": analyze_log}


def main() -> None:
    server = create_server()
    print(f"AI SOC API scaffold ready: {list(server)}")


if __name__ == "__main__":
    main()