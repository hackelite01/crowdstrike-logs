# main.py
import argparse
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()  # must precede all os.environ access

from collector.alerts import AlertsCollector
from collector.api_client import ApiClient, RateLimitController
from collector.audit_events import AuditEventsCollector
from collector.auth import AuthManager
from collector.base import BaseCollector
from collector.hosts import HostsCollector
from output.dispatcher import OutputDispatcher
from output.http_post import HttpPostOutput
from output.json_file import JsonFileOutput
from output.relp import RelpOutput
from output.syslog_tcp import SyslogTcpOutput
from state.manager import StateManager
from utils.config import load_config
from utils.logger import setup_logging
from utils.metrics import MetricsCollector

logger = logging.getLogger("main")

CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.yaml")
RELOAD_TRIGGER = Path("reload.trigger")
WATCHDOG_INTERVAL = 30
RESTART_BACKOFF_BASE = 10
RESTART_BACKOFF_MAX = 120
RESTART_RECOVERY_SECONDS = 300


def build_output_handlers(cfg: dict):
    handlers = []
    out_cfg = cfg.get("outputs", {})
    client_name = cfg.get("collection", {}).get("tag", "client")

    jf = out_cfg.get("json_file", {})
    if jf.get("enabled"):
        handlers.append(JsonFileOutput({**jf, "client_name": client_name}))

    syslog = out_cfg.get("syslog_tcp", {})
    if syslog.get("enabled"):
        handlers.append(SyslogTcpOutput(syslog))

    relp = out_cfg.get("relp", {})
    if relp.get("enabled"):
        handlers.append(RelpOutput(relp))

    http = out_cfg.get("http_post", {})
    if http.get("enabled"):
        handlers.append(HttpPostOutput(http))

    return handlers


def build_collectors(
    cfg: dict,
    api_client: ApiClient,
    state_manager: StateManager,
    queue: Queue,
) -> List[BaseCollector]:
    collection_cfg = cfg.get("collection", {})
    sources = collection_cfg.get("sources", {})
    collectors = []

    if sources.get("alerts", {}).get("enabled", False):
        collectors.append(AlertsCollector(
            api_client=api_client, state_manager=state_manager,
            output_queue=queue, config=sources["alerts"],
            global_config=collection_cfg,
        ))

    if sources.get("audit_events", {}).get("enabled", False):
        collectors.append(AuditEventsCollector(
            api_client=api_client, state_manager=state_manager,
            output_queue=queue, config=sources["audit_events"],
            global_config=collection_cfg,
        ))

    if sources.get("hosts", {}).get("enabled", False):
        collectors.append(HostsCollector(
            api_client=api_client, state_manager=state_manager,
            output_queue=queue, config=sources["hosts"],
            global_config=collection_cfg,
        ))

    return collectors


def _parse_since(value: str) -> str:
    """Parse a date/datetime string into a UTC ISO-8601 timestamp."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Cannot parse date '{value}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="CrowdStrike log collector")
    parser.add_argument(
        "--from",
        dest="since",
        metavar="DATE",
        type=_parse_since,
        help="Fetch events starting from this date (e.g. 2026-03-01 or 2026-03-01T12:00:00Z). "
             "Overrides saved state. Without this flag, resumes from last saved position.",
    )
    args = parser.parse_args()

    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    cfg = load_config(CONFIG_PATH)

    state_manager = StateManager("state.json")

    if args.since:
        collection_cfg = cfg.get("collection", {})
        sources = collection_cfg.get("sources", {})
        for source in ("alerts", "audit_events", "hosts"):
            if sources.get(source, {}).get("enabled", False):
                state_manager.update_source(source, args.since, "")
        logger.info("State reset: collecting from %s", args.since)

    metrics = MetricsCollector()

    falcon_cfg = cfg["falcon"]
    auth = AuthManager(
        base_url=falcon_cfg["base_url"],
        client_id=falcon_cfg["client_id"],
        client_secret=falcon_cfg["client_secret"],
        refresh_buffer_seconds=falcon_cfg.get("token_refresh_buffer_seconds", 300),
    )

    rl = RateLimitController()
    api_client = ApiClient(auth, rl, falcon_cfg["base_url"])

    queue_cfg = cfg.get("queue", {})
    queue: Queue = Queue(maxsize=queue_cfg.get("maxsize", 10000))

    handlers = build_output_handlers(cfg)
    collectors = build_collectors(cfg, api_client, state_manager, queue)

    dispatcher = OutputDispatcher(queue, handlers, metrics)
    dispatcher.start()

    for c in collectors:
        c.start()
    logger.info("Started %d collector(s)", len(collectors))

    # Metrics emit thread
    metrics_cfg = cfg.get("metrics", {})
    if metrics_cfg.get("enabled", True):
        metrics_thread = threading.Thread(
            target=metrics.emit_loop,
            args=(metrics_cfg.get("log_interval_seconds", 60), cfg.get("collection", {}).get("tag", "")),
            daemon=True,
            name="metrics-emitter",
        )
        metrics_thread.start()

    # Shutdown event
    shutdown = threading.Event()
    restart_delays: Dict[str, int] = {}
    last_alive: Dict[str, float] = {c.name: time.time() for c in collectors}

    def _handle_shutdown(signum, frame):  # noqa: ANN001
        logger.info("Shutdown signal received")
        shutdown.set()

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    try:
        while not shutdown.is_set():
            # Hot reload check
            if RELOAD_TRIGGER.exists():
                logger.info("Reload trigger detected — reloading config")
                try:
                    new_cfg = load_config(CONFIG_PATH)
                    cfg = new_cfg
                    logger.info("Config reloaded — new settings apply on next collector restart")
                except Exception as exc:
                    logger.error("Config reload failed: %s", exc)
                finally:
                    RELOAD_TRIGGER.unlink(missing_ok=True)

            # Watchdog
            for collector in collectors:
                if not collector.is_alive():
                    name = collector.name
                    delay = restart_delays.get(name, RESTART_BACKOFF_BASE)
                    logger.critical("Collector %s died — restarting in %ds", name, delay)
                    shutdown.wait(delay)
                    restart_delays[name] = min(delay * 2, RESTART_BACKOFF_MAX)
                    if shutdown.is_set():
                        break
                    last_alive[name] = 0.0
                    # Rebuild and restart the same collector type
                    new_collectors = build_collectors(cfg, api_client, state_manager, queue)
                    for nc in new_collectors:
                        if nc.name == collector.name:
                            nc.start()
                            collectors[collectors.index(collector)] = nc
                            break
                else:
                    # Reset backoff after sustained uptime
                    if time.time() - last_alive.get(collector.name, 0) > RESTART_RECOVERY_SECONDS:
                        restart_delays[collector.name] = RESTART_BACKOFF_BASE
                        last_alive[collector.name] = time.time()

            shutdown.wait(WATCHDOG_INTERVAL)

    finally:
        logger.info("Shutting down — stopping collectors")
        for c in collectors:
            c.stop()
        for c in collectors:
            c.join(timeout=60)   # wait for in-flight poll to complete
        queue.join()             # drain remaining events before stopping dispatcher
        dispatcher.stop()
        dispatcher.close_handlers()
        auth.revoke()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
