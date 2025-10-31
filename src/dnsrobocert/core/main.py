#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import tempfile
import threading
import traceback
from typing import Any, Callable, Iterable

import coloredlogs
import yaml

from dnsrobocert import get_version
from dnsrobocert.core import background, certbot, config, legacy, utils

LOGGER = logging.getLogger(__name__)
coloredlogs.install(logger=LOGGER)

_FALLBACK_POLL_INTERVAL_SECONDS = 5.0

try:  # pragma: no cover - optional dependency
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    _WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    FileSystemEventHandler = object  # type: ignore[misc,assignment]
    Observer = None  # type: ignore[misc,assignment]
    _WATCHDOG_AVAILABLE = False


class _ConfigEventHandler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, paths: Iterable[str], callback: Callable[[], None]) -> None:
        super().__init__()
        self._callback = callback
        self._lock = threading.Lock()
        self._paths: set[str] = set()
        self.update_targets(paths)

    def update_targets(self, paths: Iterable[str]) -> None:
        with self._lock:
            self._paths = {os.path.abspath(path) for path in paths if path}

    def _matches(self, candidate: str | None) -> bool:
        if not candidate:
            return False
        with self._lock:
            return os.path.abspath(candidate) in self._paths

    def on_any_event(self, event: Any) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return

        if self._matches(getattr(event, "src_path", None)) or self._matches(
            getattr(event, "dest_path", None)
        ):
            self._callback()


def _stat_signature(path: str) -> tuple[int, int] | None:
    try:
        stats = os.stat(path)
    except FileNotFoundError:
        return None
    except OSError as error:  # pragma: no cover - unlikely platform-specific error
        LOGGER.debug("Failed to stat %s: %s", path, error)
        return None

    return (int(stats.st_mtime_ns), stats.st_size)


def _process_config(
    config_path: str,
    directory_path: str,
    runtime_config_path: str,
    lock: threading.Lock,
) -> None:
    dnsrobocert_config = config.load(config_path)

    if not dnsrobocert_config:
        return

    if dnsrobocert_config.get("draft"):
        LOGGER.info("Configuration file is in draft mode: no action will be done.")
        return

    with open(runtime_config_path, "w") as f:
        f.write(yaml.dump(dnsrobocert_config))

    utils.configure_certbot_workspace(dnsrobocert_config, directory_path)

    LOGGER.info("Registering ACME account if needed.")
    certbot.account(runtime_config_path, directory_path, lock)

    LOGGER.info("Creating missing certificates if needed (~1min for each)")
    certbot._issue(runtime_config_path, directory_path, lock)


class _Daemon:
    def __init__(self) -> None:
        self._shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

    def shutdown(self, _signum: Any, _frame: Any) -> None:
        self._shutdown_event.set()

    def do_shutdown(self) -> bool:
        return self._shutdown_event.is_set()

    def wait_or_shutdown(self, timeout: float) -> bool:
        """Wait for timeout or until shutdown is requested. Returns True if shutdown was requested."""
        return self._shutdown_event.wait(timeout)


def _watch_config(config_path: str, directory_path: str) -> None:
    LOGGER.info(f"Starting DNSroboCert {get_version()}.")

    with tempfile.TemporaryDirectory() as workspace:
        runtime_config_path = os.path.join(workspace, "dnsrobocert-runtime.yml")
        certbot_lock = threading.Lock()

        with background.worker(runtime_config_path, directory_path, certbot_lock):
            daemon = _Daemon()
            previous_digest: bytes | None = None
            previous_signature: tuple[int, int] | None = None
            current_effective_path: str | None = None

            handler: _ConfigEventHandler | None = None
            observer: Observer | None = None
            change_event: threading.Event | None

            if _WATCHDOG_AVAILABLE:
                change_event = threading.Event()
                handler = _ConfigEventHandler([config_path], change_event.set)
                config_dir = os.path.abspath(os.path.dirname(config_path) or ".")

                try:
                    observer = Observer()
                    observer.schedule(handler, config_dir, recursive=False)
                    observer.start()
                    LOGGER.debug(
                        "Using watchdog observer to monitor %s for configuration changes.",
                        config_path,
                    )
                except Exception as error:  # pragma: no cover - instantiation/schedule failure is rare
                    LOGGER.warning(
                        "Failed to start watchdog observer (%s). Falling back to polling.",
                        error,
                    )
                    observer = None
                    handler = None
                    change_event = None
            else:
                change_event = None
                observer = None
                LOGGER.info(
                    "watchdog not available; falling back to polling every %.1f seconds.",
                    _FALLBACK_POLL_INTERVAL_SECONDS,
                )

            def maybe_reload(force: bool = False) -> None:
                nonlocal previous_digest, previous_signature, current_effective_path

                try:
                    generated_config_path = legacy.migrate(config_path)
                    effective_config_path = (
                        generated_config_path if generated_config_path else config_path
                    )

                    if handler:
                        handler.update_targets({config_path, effective_config_path})

                    signature = _stat_signature(effective_config_path)
                    if (
                        not force
                        and effective_config_path == current_effective_path
                        and signature == previous_signature
                    ):
                        return

                    digest: bytes | None
                    if signature is None:
                        digest = None
                    else:
                        digest = utils.digest(effective_config_path)

                    should_process = (
                        force
                        or effective_config_path != current_effective_path
                        or digest != previous_digest
                    )

                    previous_signature = signature
                    current_effective_path = effective_config_path
                    previous_digest = digest

                    if should_process:
                        _process_config(
                            effective_config_path,
                            directory_path,
                            runtime_config_path,
                            certbot_lock,
                        )
                except BaseException as error:
                    LOGGER.error("An error occurred during DNSroboCert watch:")
                    LOGGER.error(error)
                    traceback.print_exc(file=sys.stderr)

            try:
                maybe_reload(force=True)

                while not daemon.do_shutdown():
                    if observer and change_event:
                        triggered = change_event.wait(timeout=1.0)
                        if daemon.do_shutdown():
                            break
                        if triggered:
                            while change_event.is_set():
                                change_event.clear()
                                maybe_reload()
                    else:
                        if daemon.wait_or_shutdown(_FALLBACK_POLL_INTERVAL_SECONDS):
                            break
                        maybe_reload()
            finally:
                if observer:
                    observer.stop()
                    observer.join(timeout=5.0)

    LOGGER.info("Exiting DNSroboCert.")


def _run_config(config_path: str, directory_path: str) -> None:
    LOGGER.info("Running DNSroboCert...")

    with tempfile.TemporaryDirectory() as workspace:
        runtime_config_path = os.path.join(workspace, "dnsrobocert-runtime.yml")
        certbot_lock = threading.Lock()

        generated_config_path = legacy.migrate(config_path)
        effective_config_path = (
            generated_config_path if generated_config_path else config_path
        )

        _process_config(
            effective_config_path,
            directory_path,
            runtime_config_path,
            certbot_lock,
        )


def main(args: list[str] | None = None) -> None:
    if not args:
        args = sys.argv[1:]

    defaults = utils.get_default_args()

    parser = argparse.ArgumentParser(description="Start dnsrobocert.")
    parser.add_argument(
        "--config",
        "-c",
        default=defaults["config"],
        help=f"set the dnsrobocert config to use (default {defaults['configDesc']})",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=defaults["directory"],
        help=f"set the directory path where certificates are stored (default: {defaults['directoryDesc']})",
    )
    parser.add_argument(
        "--one-shot",
        "-o",
        action="store_true",
        help="if set, DNSroboCert will process only once certificates (creation, renewal, deletion) then return immediately",
    )

    parsed_args = parser.parse_args(args)

    utils.validate_snap_environment(parsed_args)

    if parsed_args.one_shot:
        _run_config(
            os.path.abspath(parsed_args.config), os.path.abspath(parsed_args.directory)
        )
    else:
        _watch_config(
            os.path.abspath(parsed_args.config), os.path.abspath(parsed_args.directory)
        )


if __name__ == "__main__":
    main()
