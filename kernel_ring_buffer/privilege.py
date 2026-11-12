#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles Kernel Ring Buffer - optional privileged collector client
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

"""Client and lifecycle helpers for optional Boot privileged inspection.

The PyQt application itself is never elevated. The root-owned helper is an
optional in-place read-only collector. It remains active only while the applet
keeps the authorised session open and is stopped when privileged access is
disabled or the applet shuts down.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

APPLET_DIR = Path(__file__).resolve().parent.parent
MANIFEST_PATH = APPLET_DIR / "applet.json"


def _load_contract() -> dict[str, Any]:
    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        contract = data.get("privileged_helper", {})
        return contract if isinstance(contract, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


CONTRACT = _load_contract()
HELPER_ID = str(CONTRACT.get("id") or "linspectacles-kernel-ring-buffer")
HELPER_VERSION = str(CONTRACT.get("version") or "unknown")
HELPER_PROTOCOL = int(CONTRACT.get("protocol") or 1)
HELPER_PATH = str(CONTRACT.get("install_path") or "/usr/libexec/linspectacles-kernel-ring-buffer-helper")
HELPER_PAYLOAD = APPLET_DIR / str(CONTRACT.get("payload") or "privileged/linspectacles-kernel-ring-buffer-helper")
EXPECTED_SHA256 = str(CONTRACT.get("sha256") or "").lower()
_PKEXEC_CANDIDATES = ("/usr/bin/pkexec", "/bin/pkexec")
_INSTALL_CANDIDATES = ("/usr/bin/install", "/bin/install")
_RM_CANDIDATES = ("/usr/bin/rm", "/bin/rm")


def helper_contract() -> dict[str, Any]:
    return dict(CONTRACT)


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _trusted_root_file(path: str) -> tuple[bool, str]:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False, f"Not installed: {path}"
    except OSError as exc:
        return False, f"Cannot inspect {path}: {exc}"
    if stat.S_ISLNK(st.st_mode):
        return False, "Refusing symbolic-link helper."
    if not stat.S_ISREG(st.st_mode):
        return False, "Privileged helper is not a regular file."
    if st.st_uid != 0:
        return False, "Privileged helper is not owned by root."
    if st.st_mode & 0o022:
        return False, "Privileged helper is writable by group/other."
    if not os.access(path, os.X_OK):
        return False, "Privileged helper is not executable."
    return True, "Trusted file attributes"


def helper_status_details() -> dict[str, Any]:
    details: dict[str, Any] = {
        "id": HELPER_ID,
        "required_version": HELPER_VERSION,
        "path": HELPER_PATH,
        "installed": False,
        "trusted": False,
        "integrity_matches": False,
        "ready": False,
        "state": "not_installed",
        "message": f"Not installed: {HELPER_PATH}",
        "expected_sha256": EXPECTED_SHA256,
        "observed_sha256": "",
    }
    try:
        os.lstat(HELPER_PATH)
        details["installed"] = True
    except FileNotFoundError:
        return details
    except OSError as exc:
        details.update(state="invalid", message=f"Cannot inspect helper: {exc}")
        return details

    trusted, why = _trusted_root_file(HELPER_PATH)
    details["trusted"] = trusted
    if not trusted:
        details.update(state="invalid", message=why)
        return details

    try:
        observed = _sha256(HELPER_PATH)
    except OSError as exc:
        details.update(state="invalid", message=f"Cannot hash installed helper: {exc}")
        return details
    details["observed_sha256"] = observed

    if not EXPECTED_SHA256:
        details.update(state="invalid", message="Applet manifest does not declare the expected helper hash.")
        return details
    if observed.lower() != EXPECTED_SHA256:
        details.update(
            state="outdated",
            message=(
                "Installed helper does not match this applet's packaged helper. "
                "Update or repair it before privileged inspection."
            ),
        )
        return details

    details.update(
        integrity_matches=True,
        ready=True,
        state="ready",
        message=f"Installed helper matches required version {HELPER_VERSION}.",
    )
    return details


def helper_status() -> tuple[bool, str]:
    details = helper_status_details()
    return bool(details["ready"]), str(details["message"])


def _find_trusted_executable(candidates: tuple[str, ...], fallback_name: str) -> tuple[str | None, str]:
    for path in candidates:
        ok, _why = _trusted_root_file(path)
        if ok:
            return path, "Ready"
    candidate = shutil.which(fallback_name)
    if candidate:
        ok, why = _trusted_root_file(candidate)
        if ok:
            return candidate, "Ready"
        return None, why
    return None, f"{fallback_name} is not installed."


def _find_trusted_pkexec() -> tuple[str | None, str]:
    return _find_trusted_executable(_PKEXEC_CANDIDATES, "pkexec")


def _validate_packaged_helper() -> tuple[bool, str]:
    try:
        st = os.lstat(HELPER_PAYLOAD)
    except OSError as exc:
        return False, f"Packaged helper is unavailable: {exc}"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return False, "Packaged helper must be a regular file and not a symbolic link."
    if not EXPECTED_SHA256:
        return False, "Applet manifest does not declare the packaged helper hash."
    try:
        observed = _sha256(HELPER_PAYLOAD)
    except OSError as exc:
        return False, f"Could not hash packaged helper: {exc}"
    if observed.lower() != EXPECTED_SHA256:
        return False, "Packaged helper integrity does not match the applet manifest."
    return True, "Ready"


def install_or_update_helper(timeout: float = 180.0) -> tuple[bool, str]:
    ok, msg = _validate_packaged_helper()
    if not ok:
        return False, msg
    pkexec, msg = _find_trusted_pkexec()
    if not pkexec:
        return False, msg
    install_bin, msg = _find_trusted_executable(_INSTALL_CANDIDATES, "install")
    if not install_bin:
        return False, msg
    if not os.path.isdir(os.path.dirname(HELPER_PATH)):
        return False, f"Helper destination directory does not exist: {os.path.dirname(HELPER_PATH)}"
    try:
        existing = os.lstat(HELPER_PATH)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        return False, f"Cannot inspect existing helper path: {exc}"
    if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
        return False, "Refusing to replace a symbolic-link or non-regular helper path; remove it explicitly first."
    try:
        result = subprocess.run(
            [
                pkexec,
                install_bin,
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0755",
                "--",
                str(HELPER_PAYLOAD),
                HELPER_PATH,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "Helper installation timed out."
    except OSError as exc:
        return False, f"Could not start helper installation: {exc}"
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "Authorization was cancelled or installation failed.").strip()
        return False, message
    details = helper_status_details()
    return bool(details["ready"]), str(details["message"])


def remove_helper(timeout: float = 180.0) -> tuple[bool, str]:
    details = helper_status_details()
    if not details["installed"]:
        return True, "Privileged helper is not installed."
    pkexec, msg = _find_trusted_pkexec()
    if not pkexec:
        return False, msg
    rm_bin, msg = _find_trusted_executable(_RM_CANDIDATES, "rm")
    if not rm_bin:
        return False, msg
    try:
        result = subprocess.run(
            [pkexec, rm_bin, "-f", "--", HELPER_PATH],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "Helper removal timed out."
    except OSError as exc:
        return False, f"Could not start helper removal: {exc}"
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "Authorization was cancelled or helper removal failed.").strip()
        return False, message
    if os.path.exists(HELPER_PATH):
        return False, "Helper still exists after the removal command completed."
    return True, "Privileged helper removed."


class PrivilegeClient:
    """Ephemeral stdio client for the root-owned helper."""

    def __init__(self) -> None:
        self.process: subprocess.Popen[str] | None = None
        self.state = "off"  # off, connecting, on, error
        self.message = "Privileged access is inactive."
        self._lock = threading.RLock()
        self._starter: threading.Thread | None = None
        self._stop_requested = False

    @property
    def enabled(self) -> bool:
        with self._lock:
            return (
                self.state == "on"
                and self.process is not None
                and self.process.poll() is None
            )

    def availability(self) -> tuple[bool, str]:
        ok, msg = helper_status()
        if not ok:
            return False, msg
        pkexec, msg = _find_trusted_pkexec()
        if not pkexec:
            return False, msg
        return True, "Privileged helper is available."

    def start_async(self) -> None:
        with self._lock:
            if self.state in ("connecting", "on"):
                return
            self._stop_requested = False
            self.state = "connecting"
            self.message = "Waiting for PolicyKit authorization…"
            self._starter = threading.Thread(target=self._start_worker, daemon=True)
            self._starter.start()

    def _start_worker(self, timeout: float = 120.0) -> None:
        ok, msg = helper_status()
        if not ok:
            with self._lock:
                self.state = "error"
                self.message = msg
            return
        pkexec, msg = _find_trusted_pkexec()
        if not pkexec:
            with self._lock:
                self.state = "error"
                self.message = msg
            return
        try:
            proc = subprocess.Popen(
                [pkexec, HELPER_PATH, "--stdio"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                close_fds=True,
            )
        except OSError as exc:
            with self._lock:
                self.state = "error"
                self.message = f"Could not start privileged helper: {exc}"
            return

        with self._lock:
            if self._stop_requested:
                try:
                    proc.terminate()
                except OSError:
                    pass
                self.state = "off"
                self.message = "Privileged access is inactive."
                return
            # Keep the authorizing pkexec process reachable so closing the
            # The owning applet can terminate it immediately when privileged access ends.
            self.process = proc

        line = self._readline(proc, timeout)
        if not line:
            rc = proc.poll()
            try:
                proc.terminate()
            except OSError:
                pass
            with self._lock:
                self.process = None
                if self._stop_requested:
                    self.state = "off"
                    self.message = "Privileged access is inactive."
                else:
                    self.state = "error"
                    self.message = (
                        "Authorization was cancelled or the helper did not start."
                        if rc is not None
                        else "Privileged helper timed out."
                    )
            return
        try:
            hello = json.loads(line)
        except json.JSONDecodeError:
            hello = {}
        if (
            hello.get("status") != "ready"
            or hello.get("protocol") != HELPER_PROTOCOL
            or hello.get("helper_id") != HELPER_ID
            or hello.get("helper_version") != HELPER_VERSION
        ):
            try:
                proc.terminate()
            except OSError:
                pass
            with self._lock:
                self.process = None
                if self._stop_requested:
                    self.state = "off"
                    self.message = "Privileged access is inactive."
                else:
                    self.state = "error"
                    self.message = "Privileged helper returned an unexpected identity or protocol."
            return

        with self._lock:
            if self._stop_requested:
                try:
                    proc.terminate()
                except OSError:
                    pass
                self.process = None
                self.state = "off"
                self.message = "Privileged access is inactive."
                return
            self.process = proc
            self.state = "on"
            self.message = "Privileged read-only /dev/kmsg access is active."

    @staticmethod
    def _readline(proc: subprocess.Popen[str], timeout: float) -> str | None:
        if proc.stdout is None:
            return None
        deadline = time.monotonic() + max(0.1, timeout)
        fd = proc.stdout.fileno()
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return proc.stdout.readline() or None
            wait = min(0.25, deadline - time.monotonic())
            ready, _, _ = select.select([fd], [], [], max(0.0, wait))
            if ready:
                return proc.stdout.readline()
        return None

    def request(self, op: str, timeout: float = 3.0, **payload: Any) -> dict[str, Any] | None:
        with self._lock:
            proc = self.process
            if self.state != "on" or proc is None or proc.poll() is not None:
                if self.state == "on":
                    self.state = "error"
                    self.message = "Privileged helper exited unexpectedly."
                return None
            if proc.stdin is None or proc.stdout is None:
                return None
            request = {"op": op}
            request.update(payload)
            try:
                proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
                proc.stdin.flush()
                line = self._readline(proc, timeout)
            except (BrokenPipeError, OSError, ValueError):
                self.state = "error"
                self.message = "Lost connection to privileged helper."
                return None
            if not line:
                # A timed-out stdio request cannot safely remain in-session: the
                # helper may still finish the old operation later, leaving that
                # response queued for the next request.  End the session instead
                # of risking protocol desynchronisation.
                self.state = "error"
                self.message = "Privileged helper did not answer in time."
                stale = self.process
                self.process = None
                if stale is not None:
                    try:
                        stale.terminate()
                        stale.wait(timeout=0.75)
                    except Exception:
                        try:
                            stale.kill()
                        except OSError:
                            pass
                return None
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                self.message = "Privileged helper returned invalid data."
                return None
            if response.get("ok") is False:
                self.message = str(response.get("error") or "Privileged helper request failed.")
            return response

    def stop(self) -> None:
        with self._lock:
            self._stop_requested = True
            proc = self.process
            self.process = None
            self.state = "off"
            self.message = "Privileged access is inactive."
        if proc is None:
            return
        try:
            if proc.poll() is None and proc.stdin:
                proc.stdin.write('{"op":"quit"}\n')
                proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass
        try:
            proc.wait(timeout=0.75)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=0.75)
            except Exception:
                try:
                    proc.kill()
                except OSError:
                    pass

    def __del__(self) -> None:
        try:
            self.stop()
        except Exception:
            pass
