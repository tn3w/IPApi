import logging
import os
import multiprocessing
from multiprocessing import Process

import uvicorn
from src.utils import load_dotenv
from src.shared_data_store import start_memory_server

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _run_memory_server(memory_port: int) -> None:
    """Run the memory server - module level function for Windows multiprocessing."""
    try:
        start_memory_server(memory_port)
    except Exception as e:
        logger.error("Memory server failed: %s", e)


def start_memory_server_process(memory_port: int) -> Process:
    """Start the memory server in a separate process."""
    process = Process(target=_run_memory_server, args=(memory_port,), daemon=True)
    process.start()
    logger.info("Memory server process started with PID: %d", process.pid)
    return process


def main() -> None:
    """Run the application with shared memory support."""
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    workers = int(os.getenv("WORKERS", "16"))
    memory_port = int(os.getenv("MEMORY_PORT", "50000"))

    logger.info(
        "Starting IPApi server at http://%s:%d with %d workers", host, port, workers
    )

    memory_server_process = start_memory_server_process(memory_port)

    try:
        os.environ["MEMORY_PORT"] = str(memory_port)

        uvicorn.run(
            "src.api:app",
            host=host,
            port=port,
            workers=workers,
            server_header=False,
            access_log=False,
            log_level="error",
        )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        if memory_server_process.is_alive():
            memory_server_process.kill()


if __name__ == "__main__":
    if os.name == "nt":
        multiprocessing.freeze_support()

    main()
