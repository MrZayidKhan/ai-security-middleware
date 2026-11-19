"""Run the gateway from this checkout with the development audit database."""
from pathlib import Path

from security_middleware.server import main


if __name__ == '__main__':
    main(default_db=Path(__file__).resolve().parents[1] / "runtime_data" / "security_events.db")
