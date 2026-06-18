"""Scheduler entrypoint — single-replica service that polls DB every 60 seconds."""
import asyncio
import logging
import os
import signal
import sys

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

POLL_INTERVAL = int(os.getenv("SCHEDULER_POLL_INTERVAL", "60"))

_shutdown = False


def _handle_signal(sig, frame):
    global _shutdown
    logger.info("received signal %s — shutting down", sig)
    _shutdown = True


async def main() -> None:
    from app.core.config import settings

    if not settings.database_url:
        logger.error("DATABASE_URL not configured")
        sys.exit(1)

    engine = create_async_engine(settings.database_url, pool_pre_ping=True)
    db_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    from app.scheduler.scheduler import run_one_tick, recover_stuck_scans, prune_old_results

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("scheduler started (poll interval: %ds)", POLL_INTERVAL)

    while not _shutdown:
        try:
            await recover_stuck_scans(db_factory)
            await prune_old_results(db_factory)
            await run_one_tick(db_factory)
        except Exception as exc:
            logger.error("tick error: %s", exc, exc_info=True)

        for _ in range(POLL_INTERVAL * 10):
            if _shutdown:
                break
            await asyncio.sleep(0.1)

    await engine.dispose()
    logger.info("scheduler stopped")


if __name__ == "__main__":
    asyncio.run(main())
