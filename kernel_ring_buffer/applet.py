#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspector Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

from __future__ import annotations

APPLET_ID = "linspectacles-kernel-ring-buffer"
APPLET_NAME = "Kernel Ring Buffer"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_VERSION = "0.0.6"

import errno
import json
import os
import re
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QTimer, QUrl
from PyQt6.QtGui import QBrush, QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .privilege import (
    HELPER_PATH,
    PrivilegeClient,
    helper_status_details,
    install_or_update_helper,
    remove_helper,
)
from ._support import (
    ColumnVisibilityController,
    MetadataHighlighter,
    NumericTableWidgetItem,
    apply_metadata_font,
    export_records_dialog,
    metadata_font_qss,
)


PRIORITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}

FACILITY_NAMES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "res0",
    13: "res1",
    14: "res2",
    15: "res3",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

KMSG_PATH = "/dev/kmsg"
KMSG_READ_SIZE = 4 * 1024 * 1024
KMSG_MAX_RECORDS = 500_000
HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")


def _permission_text(text):
    low = str(text or "").lower()
    return any(token in low for token in (
        "permission denied",
        "access denied",
        "operation not permitted",
        "not permitted",
    ))


def _string(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_string(item) for item in value)
    if isinstance(value, tuple):
        return ", ".join(_string(item) for item in value)
    if isinstance(value, dict):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            return str(value)
    return str(value)


def _priority_display(code):
    try:
        number = int(code)
    except (TypeError, ValueError):
        return "Not reported"
    return f"{number} - {PRIORITY_NAMES.get(number, 'Unknown')}"


def _facility_display(code):
    try:
        number = int(code)
    except (TypeError, ValueError):
        return "Not reported"
    return f"{number} - {FACILITY_NAMES.get(number, 'unknown')}"


def _monotonic_display(usec):
    try:
        value = int(usec)
    except (TypeError, ValueError):
        return "Not reported"
    seconds, micros = divmod(value, 1_000_000)
    return f"{seconds}.{micros:06d} s"


def _decode_kernel_escapes(text):
    """Decode the kernel's \\xHH escaping without losing UTF-8 byte sequences."""
    source = str(text or "")
    out = bytearray()
    index = 0
    while index < len(source):
        if (
            source[index:index + 2] == "\\x"
            and index + 4 <= len(source)
            and re.fullmatch(r"[0-9A-Fa-f]{2}", source[index + 2:index + 4])
        ):
            out.append(int(source[index + 2:index + 4], 16))
            index += 4
            continue
        out.extend(source[index].encode("utf-8", errors="replace"))
        index += 1
    return out.decode("utf-8", errors="replace")


def _single_line(text):
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _raw_one_line(text):
    # JSON string notation keeps every byte-derived character/newline visible
    # without letting the metadata highlighter mistake message colons for keys.
    return json.dumps(str(text or ""), ensure_ascii=False)


def _read_kmsg_snapshot():
    """Return all records currently available through /dev/kmsg.

    /dev/kmsg keeps reader position per file descriptor. SEEK_SET 0 requests the
    oldest record still retained in the ring. Reading does not clear the buffer.
    """
    fd = None
    records = []
    overrun_events = 0
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(KMSG_PATH, flags)
        os.lseek(fd, 0, os.SEEK_SET)

        while len(records) < KMSG_MAX_RECORDS:
            try:
                payload = os.read(fd, KMSG_READ_SIZE)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno == errno.EPIPE:
                    # Records were overwritten while this reader was open.
                    # The kernel advances us to the next available record.
                    overrun_events += 1
                    continue
                raise
            if not payload:
                break
            records.append(payload.decode("utf-8", errors="replace"))

        truncated = len(records) >= KMSG_MAX_RECORDS
        return records, overrun_events, truncated
    finally:
        if fd is not None:
            os.close(fd)


def _parse_kmsg_record(raw_record, *, access="Standard access"):
    raw_record = str(raw_record or "")
    stripped = raw_record.rstrip("\x00")
    first_line, sep, remainder = stripped.partition("\n")

    if ";" not in first_line:
        record = {
            "sequence": None,
            "sequence_display": "Not reported",
            "monotonic_us": None,
            "monotonic": "Not reported",
            "syslog_prefix": None,
            "priority_code": None,
            "priority": "Not reported",
            "facility_code": None,
            "facility": "Not reported",
            "flags": "Not reported",
            "fragment": "Not reported",
            "caller": "",
            "caller_type": "",
            "caller_id": "",
            "subsystem": "",
            "device": "",
            "message": _decode_kernel_escapes(first_line),
            "message_summary": _single_line(_decode_kernel_escapes(first_line)),
            "header_extensions": [],
            "context_tags": [],
            "context_lines": [],
            "context_entries": [],
            "raw_header": "",
            "raw_record": raw_record,
            "parse_error": "Record does not contain the required /dev/kmsg header terminator ';'.",
            "access": access,
            "interface": KMSG_PATH,
        }
        record["search_blob"] = _record_search_blob(record)
        return record

    raw_header, raw_message = first_line.split(";", 1)
    fields = raw_header.split(",")

    def _to_int(index):
        try:
            return int(fields[index])
        except (IndexError, TypeError, ValueError):
            return None

    syslog_prefix = _to_int(0)
    sequence = _to_int(1)
    monotonic_us = _to_int(2)

    priority_code = None
    facility_code = None
    if syslog_prefix is not None:
        priority_code = syslog_prefix & 0x7
        facility_code = syslog_prefix >> 3

    flags = fields[3] if len(fields) >= 4 and fields[3] != "" else "Not reported"
    extension_fields = list(fields[4:]) if len(fields) > 4 else []

    caller = ""
    caller_type = ""
    caller_id = ""
    for field in extension_fields:
        if field.startswith("caller="):
            caller = field.split("=", 1)[1]
            if caller.startswith("T") and caller[1:].isdigit():
                caller_type = "Thread"
                caller_id = caller[1:]
            elif caller.startswith("C") and caller[1:].isdigit():
                caller_type = "CPU"
                caller_id = caller[1:]
            break

    context_tags = []
    context_lines = []
    context_entries = []
    if sep:
        for line in remainder.splitlines():
            if not line:
                continue
            decoded_line = _decode_kernel_escapes(line[1:] if line.startswith(" ") else line)
            context_lines.append(decoded_line)
            if line.startswith(" ") and "=" in line:
                key_raw, value_raw = line[1:].split("=", 1)
                key = _decode_kernel_escapes(key_raw)
                value = _decode_kernel_escapes(value_raw)
                context_tags.append((key, value))
                context_entries.append({"key": key, "value": value, "line": decoded_line})
            else:
                context_entries.append({"key": "", "value": "", "line": decoded_line})

    subsystem = next((value for key, value in context_tags if key == "SUBSYSTEM"), "")
    device = next((value for key, value in context_tags if key == "DEVICE"), "")

    message = _decode_kernel_escapes(raw_message)

    record = {
        "sequence": sequence,
        "sequence_display": str(sequence) if sequence is not None else "Not reported",
        "monotonic_us": monotonic_us,
        "monotonic": _monotonic_display(monotonic_us),
        "syslog_prefix": syslog_prefix,
        "priority_code": priority_code,
        "priority": _priority_display(priority_code),
        "facility_code": facility_code,
        "facility": _facility_display(facility_code),
        "flags": flags,
        "fragment": "Yes" if isinstance(flags, str) and "c" in flags else "No",
        "caller": caller,
        "caller_type": caller_type,
        "caller_id": caller_id,
        "subsystem": subsystem,
        "device": device,
        "message": message,
        "message_summary": _single_line(message),
        "header_extensions": extension_fields,
        "context_tags": context_tags,
        "context_lines": context_lines,
        "context_entries": context_entries,
        "raw_header": raw_header,
        "raw_record": raw_record,
        "parse_error": "",
        "access": access,
        "interface": KMSG_PATH,
    }
    record["search_blob"] = _record_search_blob(record)
    return record


def _record_search_blob(record):
    parts = []
    for key, value in record.items():
        if key == "search_blob":
            continue
        parts.append(str(key))
        if key == "context_tags":
            for tag_key, tag_value in value or []:
                parts.extend((str(tag_key), str(tag_value)))
        else:
            parts.append(_string(value))
    return " ".join(parts).lower()


def _source_status(state, detail, count=0):
    return {
        "name": "Kernel Ring Buffer",
        "state": str(state),
        "detail": str(detail),
        "count": int(count or 0),
    }


class KernelRingBufferOptionsDialog(QDialog):
    def __init__(self, owner, initial_tab=0):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Kernel Ring Buffer")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        configuration_page = QWidget()
        al = QVBoxLayout(configuration_page)
        al.setContentsMargins(12, 12, 12, 12)
        al.setSpacing(10)
        h = QLabel("Kernel ring appearance")
        f = h.font(); f.setBold(True); h.setFont(f)
        al.addWidget(h)
        n = QLabel(
            "Metadata Details presents every native /dev/kmsg field retained for the selected record. "
            "Display settings are remembered."
        )
        n.setWordWrap(True)
        al.addWidget(n)

        row = QHBoxLayout()
        row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentIndex(1 if owner.details_orientation == "vertical" else 0)
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        row.addWidget(self.layout_combo)
        row.addStretch(1)
        al.addLayout(row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        al.addWidget(self.show_metadata_panel)

        scan_note = QLabel(
            "F3 hides/restores Metadata Details. Shift+F5 repeats the current scan. "
            "Ctrl+L toggles the details layout. Ctrl+/ opens Options. "
            "Priority: Ctrl+0…Ctrl+7 = Emergency…Debug; Ctrl+A = All; "
            "Ctrl+N = Not reported."
        )
        scan_note.setWordWrap(True)
        al.addWidget(scan_note)

        al.addStretch(1)
        tabs.addTab(configuration_page, "Appearance")

        helper_page = QWidget()
        helper_layout = QVBoxLayout(helper_page)
        helper_layout.setContentsMargins(12, 12, 12, 12)
        helper_layout.setSpacing(10)

        helper_heading = QLabel("Privileged Helper")
        helper_heading_font = helper_heading.font()
        helper_heading_font.setBold(True)
        helper_heading_font.setPointSize(max(helper_heading_font.pointSize(), 11))
        helper_heading.setFont(helper_heading_font)
        helper_layout.addWidget(helper_heading)

        helper_note = QLabel(
            "Kernel Ring Buffer is usable with ordinary access whenever Linux permits /dev/kmsg reads. "
            "The optional helper is a separately installed, root-owned, read-only collector; the GUI itself "
            "is never elevated. Install/update/repair and removal use PolicyKit only for the fixed helper path."
        )
        helper_note.setWordWrap(True)
        helper_layout.addWidget(helper_note)

        helper_provenance_note = QLabel(
            "Privileged read-only /dev/kmsg access · amber data = helper-sourced"
        )
        helper_provenance_note.setWordWrap(True)
        helper_provenance_note.setStyleSheet(
            "color: #f2d18b; font-weight: bold;"
        )
        helper_layout.addWidget(helper_provenance_note)

        self.helper_status_label = QLabel()
        self.helper_status_label.setWordWrap(True)
        self.helper_status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        helper_layout.addWidget(self.helper_status_label)

        self.helper_path_label = QLabel(f"System location: {HELPER_PATH}")
        self.helper_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        helper_layout.addWidget(self.helper_path_label)

        self.helper_access_label = QLabel()
        self.helper_access_label.setWordWrap(True)
        helper_layout.addWidget(self.helper_access_label)

        helper_actions = QHBoxLayout()
        self.install_helper_button = QPushButton("Install or Update/Repair Helper...")
        self.install_helper_button.clicked.connect(self._install_or_update_helper)
        helper_actions.addWidget(self.install_helper_button)
        self.remove_helper_button = QPushButton("Remove Helper...")
        self.remove_helper_button.clicked.connect(self._remove_helper)
        helper_actions.addWidget(self.remove_helper_button)
        helper_actions.addStretch(1)
        helper_layout.addLayout(helper_actions)
        helper_layout.addStretch(1)

        tabs.addTab(helper_page, "Helper")

        sources_page = QWidget()
        sl = QVBoxLayout(sources_page)
        sl.setContentsMargins(12, 12, 12, 12)
        sl.setSpacing(10)
        h = QLabel("Data Source")
        f = h.font(); f.setBold(True); f.setPointSize(max(f.pointSize(), 11)); h.setFont(f)
        sl.addWidget(h)
        n = QLabel("Sources lists only the external interface from which Kernel Ring Buffer reads records.")
        n.setWordWrap(True)
        sl.addWidget(n)
        self.sources_text = QTextEdit()
        self.sources_text.setReadOnly(True)
        self.sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen = getattr(owner, "_metadata_font", None)
        font_rule = ""
        if chosen is not None:
            self.sources_text.setFont(chosen)
            self.sources_text.document().setDefaultFont(chosen)
            font_rule = metadata_font_qss(chosen)
        self.sources_text.setStyleSheet(
            "QTextEdit { "
            + font_rule
            + " background-color: #151719; color: #dcdcdc; "
              "border: 1px solid #333333; }"
        )

        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))

        cursor = self.sources_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in owner.sources_report().splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        self.sources_text.setTextCursor(cursor)
        self.sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sl.addWidget(self.sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        export_page = QWidget()
        el = QVBoxLayout(export_page)
        el.setContentsMargins(12, 12, 12, 12)
        el.setSpacing(10)
        h = QLabel("Export details")
        f = h.font(); f.setBold(True); h.setFont(f)
        el.addWidget(h)
        n = QLabel("Select the kernel-ring fields to include in the export.")
        n.setWordWrap(True)
        el.addWidget(n)

        self.export_checks = []
        for key, label in (
            ("sequence_display", "Sequence"),
            ("monotonic", "Monotonic Time"),
            ("monotonic_us", "Monotonic Timestamp (µs)"),
            ("syslog_prefix", "Syslog Prefix"),
            ("priority", "Priority"),
            ("priority_code", "Priority Code"),
            ("facility", "Facility"),
            ("facility_code", "Facility Code"),
            ("flags", "Flags"),
            ("fragment", "Fragment"),
            ("caller", "Caller"),
            ("caller_type", "Caller Type"),
            ("caller_id", "Caller ID"),
            ("subsystem", "Subsystem"),
            ("device", "Device"),
            ("message", "Message"),
            ("header_extensions_display", "Optional Header Fields"),
            ("context_tags_display", "Machine-readable Context"),
            ("access", "Access"),
            ("raw_record", "Raw /dev/kmsg Record"),
        ):
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            el.addWidget(checkbox)
            self.export_checks.append((key, label, checkbox))

        self.export_metadata = QCheckBox("Metadata Details")
        self.export_metadata.setChecked(False)
        el.addWidget(self.export_metadata)
        el.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        button = QPushButton("Export...")
        button.clicked.connect(self._export_selected)
        row.addWidget(button)
        el.addLayout(row)
        tabs.addTab(export_page, "Export")

        about_page = QWidget()
        bl = QVBoxLayout(about_page)
        bl.setContentsMargins(24, 20, 24, 18)
        bl.setSpacing(8)
        icon = QLabel()
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(112, 112)
        ip = Path(__file__).resolve().parent / "icon.png"
        if ip.is_file():
            pm = QPixmap(str(ip))
            if not pm.isNull():
                icon.setPixmap(pm.scaled(
                    112, 112,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                ))
        bl.addWidget(icon, alignment=Qt.AlignmentFlag.AlignHCenter)
        name = QLabel("<h2 style='margin:0'>Kernel Ring Buffer</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(name)
        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(version)
        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(slogan)
        desc = QLabel(
            "A read-only LinSpectacles applet for the current kernel printk ring buffer. "
            "It reads /dev/kmsg directly so native record header fields and machine-readable "
            "continuation metadata are preserved instead of flattened by a presentation command."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(desc)
        det = QLabel(
            f"<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            "<a href='https://github.com/linspectacles/'>linspectacles</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        det.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        det.setOpenExternalLinks(True)
        det.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(det)
        cp = QLabel("Copyright © 2026 <a href='https://github.com/brunonlinespace'>brunonlinespace</a>")
        cp.setOpenExternalLinks(True)
        cp.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(cp)
        lic = QLabel("Licensed under GNU GPLv3 or later.")
        lic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(lic)
        ru = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "README.md")).toString()
        lu = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{ru}'>README</a>"
            "&nbsp;·&nbsp; "
            f"<a href='{lu}'>License</a>"
            "&nbsp;·&nbsp; "
            "<a href='https://github.com/linspectacles/kernel-ring-buffer'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(links)
        bl.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        tabs.setCurrentIndex(max(0, min(int(initial_tab), tabs.count() - 1)))
        self._refresh_helper_ui()

    def _layout_changed(self, text):
        orientation = "vertical" if str(text).lower().startswith("vertical") else "horizontal"
        self.owner.set_details_orientation(orientation, persist=True)

    def _metadata_panel_changed(self, checked):
        self.owner.set_metadata_panel_visible(bool(checked), persist=True)

    def _export_selected(self):
        if not self.owner._has_scanned:
            QMessageBox.information(self, "Export", "Kernel ring records have not been scanned yet.")
            return
        selected = [
            (key, label)
            for key, label, checkbox in self.export_checks
            if checkbox.isChecked()
        ]
        if self.export_metadata.isChecked():
            selected.append(("metadata_details", "Metadata Details"))
        if not selected:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return

        records = []
        for record in self.owner._records:
            item = self.owner._exportable_record(record)
            if self.export_metadata.isChecked():
                item["metadata_details"] = self.owner.metadata_details_for_export(record)
            records.append(item)

        path = export_records_dialog(
            self,
            APPLET_NAME,
            records,
            columns=selected,
            sections={"Source": KMSG_PATH},
        )
        if path:
            self.owner.set_status(f"Exported kernel ring records to {path}")


    def _refresh_helper_ui(self):
        details = helper_status_details()
        state = str(details.get("state") or "unknown")
        state_text = {
            "ready": "Installed and ready",
            "not_installed": "Not installed",
            "outdated": "Update or repair required",
            "invalid": "Installed helper is not trusted/usable",
        }.get(state, state.replace("_", " ").title())
        self.helper_status_label.setText(
            f"Status: {state_text}\n{details.get('message', '')}\n"
            f"Required helper version: {details.get('required_version', 'unknown')}"
        )

        active = bool(self.owner.privilege.enabled or self.owner.privilege.state == "connecting")
        self.install_helper_button.setEnabled(not active)
        self.remove_helper_button.setEnabled(bool(details.get("installed")) and not active)

        if self.owner.privilege.enabled:
            self.helper_access_label.setText(
                "Privileged session: Active — helper management is disabled until privileged access ends."
            )
        elif self.owner.privilege.state == "connecting":
            self.helper_access_label.setText(
                "Privileged session: Authorizing… — helper management is temporarily disabled."
            )
        else:
            available, why = self.owner.privilege.availability()
            self.helper_access_label.setText(
                "Privileged access: Ready" if available else f"Privileged access: Unavailable — {why}"
            )

    def _install_or_update_helper(self):
        answer = QMessageBox.question(
            self,
            "Kernel Ring Buffer Privileged Helper",
            "Install, update, or repair the optional root-owned Kernel Ring Buffer helper?\n\n"
            "PolicyKit will request administrator authorization. The helper exposes exactly one fixed "
            "read-only operation: snapshot /dev/kmsg. The GUI itself is not elevated.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.install_helper_button.setEnabled(False)
        QApplication.processEvents()
        ok, message = install_or_update_helper()
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Kernel Ring Buffer Privileged Helper", message
        )
        self.owner._update_privilege_ui(force=True)
        self._refresh_helper_ui()

    def _remove_helper(self):
        answer = QMessageBox.question(
            self,
            "Remove Kernel Ring Buffer Privileged Helper",
            "Remove the optional root-owned Kernel Ring Buffer helper?\n\n"
            "Ordinary-user /dev/kmsg inspection will remain available where Linux permissions allow it. "
            "PolicyKit will request administrator authorization for removal.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        ok, message = remove_helper()
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Kernel Ring Buffer Privileged Helper", message
        )
        self.owner._update_privilege_ui(force=True)
        self._refresh_helper_ui()


class KernelRingBufferInspector(QWidget):
    COLUMNS = [
        ("sequence_display", "Sequence", 105, "right"),
        ("monotonic", "Monotonic Time", 145, "right"),
        ("priority", "Priority", 125, "left"),
        ("facility", "Facility", 105, "left"),
        ("caller", "Caller", 90, "left"),
        ("flags", "Flags", 65, "left"),
        ("subsystem", "Subsystem", 125, "left"),
        ("device", "Device", 185, "left"),
        ("message_summary", "Message", 520, "left"),
    ]

    # In-place privilege follows Resource Monitor's lifecycle model while
    # using the established SELinux amber/gold provenance palette.
    PRIVILEGED_ACCENT = "#d6a23d"
    PRIVILEGED_ACCENT_LIGHT = "#f2d18b"
    PRIVILEGED_DATA = "#e5bd70"
    PRIVILEGED_DEEP = "#6a4b0c"
    PRIVILEGE_ACTIVE_QSS = (
        "QPushButton { background: #6a4b0c; color: #fff4d2; "
        "border: 1px solid #d6a23d; border-radius: 4px; "
        "padding: 5px 10px; font-weight: 600; } "
        "QPushButton:hover { border-color: #f2c96d; }"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.privilege = PrivilegeClient()
        self._last_priv_state = self.privilege.state
        self._shutting_down = False
        self._records = []
        self._visible_records = []
        self._source_status = None
        self._has_scanned = False
        self._metadata_font = None
        self._column_host_callback = None
        self._applet_active = True
        self.metadata_panel_visible = True

        # Ordinary metadata palette.
        self._key_color = "#4ec9b0"
        self._value_color = "#ce9178"
        self._text_bg = "#1e1e1e"
        self._text_fg = "#dcdcdc"
        self._status_bg = "transparent"
        self._status_fg = "#dcdcdc"

        self.details_orientation = "horizontal"
        self._setup_ui()
        self._load_display_preferences()
        self._setup_shortcuts()

        # Resource Monitor-style in-place helper lifecycle with SELinux-style
        # ephemeral deactivation: leaving the applet ends the helper session.
        self._priv_timer = QTimer(self)
        self._priv_timer.setInterval(300)
        self._priv_timer.timeout.connect(self._update_privilege_ui)
        self._priv_timer.start()
        self._update_privilege_ui(force=True)

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top = QHBoxLayout()
        self.stats_label = QLabel("Kernel Ring Records: Not scanned")
        font = self.stats_label.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        self.stats_label.setFont(font)
        top.addWidget(self.stats_label)
        top.addStretch(1)

        self.priv_button = QPushButton("Privileged: Off")
        self.priv_button.setToolTip(
            "Start or end the optional in-place privileged read-only /dev/kmsg collector. "
            "The Kernel Ring Buffer GUI itself never runs as root."
        )
        self.priv_button.clicked.connect(self.toggle_privileged)
        top.addWidget(self.priv_button)

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.scan)
        top.addWidget(self.scan_btn)

        self.options_btn = QPushButton("Options...")
        self.options_btn.clicked.connect(self.show_options)
        top.addWidget(self.options_btn)
        root.addLayout(top)

        filters = QHBoxLayout()

        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-weight:600;")
        filters.addWidget(search_label)
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search all kernel-ring record fields...")
        self.search_entry.setMaximumWidth(340)
        self.search_entry.textChanged.connect(self._apply_filter)
        filters.addWidget(self.search_entry)

        facility_label = QLabel("Facility:")
        facility_label.setStyleSheet("font-weight:600;")
        filters.addWidget(facility_label)
        self.facility_combo = QComboBox()
        self.facility_combo.addItem("All", "")
        self.facility_combo.currentIndexChanged.connect(self._apply_filter)
        filters.addWidget(self.facility_combo)

        priority_label = QLabel("Priority:")
        priority_label.setStyleSheet("font-weight:600;")
        filters.addWidget(priority_label)
        self.priority_combo = QComboBox()
        self.priority_combo.addItem("All", "")
        for value in range(8):
            self.priority_combo.addItem(_priority_display(value), str(value))
        self.priority_combo.addItem("Not reported", "__not_reported__")
        self.priority_combo.currentIndexChanged.connect(self._apply_filter)
        filters.addWidget(self.priority_combo)

        # Match Facility to the established Priority selector's natural width.
        self.facility_combo.setMinimumWidth(self.priority_combo.sizeHint().width())

        self.filter_label = QLabel("")
        ff = self.filter_label.font()
        ff.setItalic(True)
        self.filter_label.setFont(ff)
        filters.addWidget(self.filter_label)
        filters.addStretch(1)
        root.addLayout(filters)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(self.splitter, 1)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels([column[1] for column in self.COLUMNS])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._selection_changed)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSortIndicatorShown(True)
        for index, (_cid, _label, width, _align) in enumerate(self.COLUMNS):
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
            self.table.setColumnWidth(index, width)

        self.column_visibility = ColumnVisibilityController(
            self.table,
            self.COLUMNS,
            self.set_status,
        )
        self.splitter.addWidget(self.table)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 0, 0, 0)

        details_label = QLabel("Metadata Details")
        df = details_label.font()
        df.setBold(True)
        df.setPointSize(max(df.pointSize(), 11))
        details_label.setFont(df)
        right_layout.addWidget(details_label)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self._metadata_font = apply_metadata_font(self.details)
        self.details_highlighter = MetadataHighlighter(self.details.document())
        self._update_details_style()
        right_layout.addWidget(self.details, 1)

        self.splitter.addWidget(right_panel)
        self.splitter.setSizes([810, 470])

        self.status_lbl = QLabel(f"Not scanned. Press Scan to read {KMSG_PATH}.")
        sf = self.status_lbl.font()
        sf.setItalic(True)
        self.status_lbl.setFont(sf)
        self.status_lbl.setFrameShape(QFrame.Shape.NoFrame)
        self.status_lbl.setContentsMargins(4, 4, 4, 4)
        root.addWidget(self.status_lbl)

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        settings = settings or {}
        self._metadata_font = apply_metadata_font(
            self.details,
            settings.get("metadata_font", ""),
        )
        self._update_details_style()
        self.column_visibility.set_changed_callback(column_visibility_callback)
        self.column_visibility.apply_hidden(settings.get("hidden_columns", []))
        self._column_host_callback = column_visibility_callback

    def set_theme_colors(
        self, text_bg, text_fg, key_fg, value_fg, status_bg, status_fg
    ):
        """Apply the same metadata/status theme contract as SELinux Inspector."""
        self._text_bg = str(text_bg)
        self._text_fg = str(text_fg)
        self._key_color = str(key_fg)
        self._value_color = str(value_fg)
        self._status_bg = str(status_bg)
        self._status_fg = str(status_fg)

        self._update_details_style()
        self.details_highlighter.set_colors(key_fg, value_fg, text_fg)
        self.status_lbl.setStyleSheet(
            f"QLabel {{ background: {status_bg}; color: {status_fg}; padding: 4px; }}"
        )

    def _update_details_style(self):
        self.details.setStyleSheet(
            "QTextEdit { "
            f"background: {self._text_bg}; color: {self._text_fg}; "
            "border: 1px solid #666; "
            f"{metadata_font_qss(self._metadata_font)} "
            "}"
        )
        if hasattr(self, "details_highlighter"):
            self.details_highlighter.set_colors(
                self._key_color, self._value_color, self._text_fg
            )

    def set_status(self, text):
        self.status_lbl.setText(str(text))

    def _update_counter(self):
        if not self._has_scanned:
            self.stats_label.setText("Kernel Ring Records: Not scanned")
        else:
            self.stats_label.setText(f"Kernel Ring Records: {len(self._records):,}")

    def _rebuild_facility_filter(self):
        previous = str(self.facility_combo.currentData() or "")
        values = sorted({
            record.get("facility_code")
            for record in self._records
            if isinstance(record.get("facility_code"), int)
        })
        self.facility_combo.blockSignals(True)
        try:
            self.facility_combo.clear()
            self.facility_combo.addItem("All", "")
            for value in values:
                self.facility_combo.addItem(_facility_display(value), str(value))
            if any(record.get("facility_code") is None for record in self._records):
                self.facility_combo.addItem("Not reported", "__not_reported__")
            index = self.facility_combo.findData(previous)
            self.facility_combo.setCurrentIndex(index if index >= 0 else 0)
        finally:
            self.facility_combo.blockSignals(False)

    def _privileged_active(self):
        return bool(self.privilege is not None and self.privilege.enabled)

    def _helper_request(self, op, *, timeout=60.0, **payload):
        if not self._privileged_active():
            return None
        response = self.privilege.request(op, timeout=timeout, **payload)
        return response if isinstance(response, dict) else None

    def _collect_ring(self):
        access = "Privileged Helper" if self._privileged_active() else "Standard access"

        if self._privileged_active():
            response = self._helper_request("kmsg_snapshot", timeout=60.0)
            if not response:
                raise PermissionError(self.privilege.message)
            if response.get("ok") is False:
                raise OSError(str(response.get("error") or "Privileged /dev/kmsg read failed."))
            raw_records = [str(item) for item in (response.get("records") or [])]
            overruns = int(response.get("overrun_events") or 0)
            truncated = bool(response.get("truncated"))
        else:
            raw_records, overruns, truncated = _read_kmsg_snapshot()

        records = [
            _parse_kmsg_record(raw, access=access)
            for raw in raw_records
        ]

        detail_parts = [f"Read {KMSG_PATH} directly."]
        if self._privileged_active():
            detail_parts.append("Access used the verified privileged helper.")
        if overruns:
            detail_parts.append(
                f"{overruns} ring-buffer overwrite event(s) occurred while the snapshot was being read."
            )
        if truncated:
            detail_parts.append(
                f"Stopped at the safety cap of {KMSG_MAX_RECORDS:,} records."
            )
        return records, " ".join(detail_parts)

    def scan(self):
        self.scan_btn.setText("Scanning...")
        self.scan_btn.setEnabled(False)
        self.set_status(f"Reading {KMSG_PATH}...")
        QApplication.processEvents()

        try:
            records, detail = self._collect_ring()
            self._records = records
            self._has_scanned = True
            self._source_status = _source_status("Observed", detail, len(records))
            self._rebuild_facility_filter()
            self._apply_filter()
            self._update_counter()

            malformed = sum(1 for record in records if record.get("parse_error"))
            status = f"Observed: {len(records):,} kernel ring record(s)."
            if malformed:
                status += f" {malformed:,} record(s) retained with parse warnings."
            self.set_status(status)

        except PermissionError as exc:
            self._records = []
            self._has_scanned = True
            detail = str(exc) or f"Permission denied reading {KMSG_PATH}."
            self._source_status = _source_status("Restricted", detail)
            self._rebuild_facility_filter()
            self._apply_filter()
            self._update_counter()
            self.set_status(
                f"Restricted: {KMSG_PATH} cannot be read with ordinary access. "
                "Enable Privileged for the same read-only source."
            )
        except OSError as exc:
            self._records = []
            self._has_scanned = True
            detail = str(exc)
            state = "Restricted" if _permission_text(detail) else "Unavailable"
            self._source_status = _source_status(state, detail)
            self._rebuild_facility_filter()
            self._apply_filter()
            self._update_counter()
            self.set_status(f"{state}: {detail}")
        except Exception as exc:
            self._records = []
            self._has_scanned = True
            self._source_status = _source_status("Unavailable", str(exc))
            self._rebuild_facility_filter()
            self._apply_filter()
            self._update_counter()
            self.set_status(f"Unavailable: {exc}")
        finally:
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("Scan Again" if self._has_scanned else "Scan")

    def _synchronize_details_after_rebuild(self, matches):
        self.details.clear()
        blocked = self.table.blockSignals(True)
        try:
            self.table.clearSelection()
            if not matches:
                self.table.setCurrentCell(-1, -1)
            else:
                self.table.setCurrentCell(0, 0)
                self.table.selectRow(0)
        finally:
            self.table.blockSignals(blocked)

        if matches:
            item = self.table.item(0, 0)
            record = (
                item.data(Qt.ItemDataRole.UserRole)
                if item is not None
                else None
            )
            if isinstance(record, dict):
                self._render_record_details(record)
        self._reset_details_to_top()

    def _apply_filter(self, *_):
        query = self.search_entry.text().strip().lower()
        priority = str(self.priority_combo.currentData() or "")
        facility = str(self.facility_combo.currentData() or "")
        visible = []

        for record in self._records:
            if priority == "__not_reported__":
                if record.get("priority_code") is not None:
                    continue
            elif priority:
                if str(record.get("priority_code")) != priority:
                    continue

            if facility == "__not_reported__":
                if record.get("facility_code") is not None:
                    continue
            elif facility:
                if str(record.get("facility_code")) != facility:
                    continue

            if query and query not in str(record.get("search_blob") or ""):
                continue
            visible.append(record)

        self._visible_records = visible

        blocked = self.table.blockSignals(True)
        try:
            self.details.clear()
            self.table.clearSelection()
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(visible))

            for row_index, record in enumerate(visible):
                for column_index, (key, _label, _width, alignment) in enumerate(self.COLUMNS):
                    value = record.get(key, "")
                    if key == "sequence_display":
                        sort_value = (
                            record.get("sequence")
                            if isinstance(record.get("sequence"), int)
                            else -1
                        )
                        item = NumericTableWidgetItem(str(value), sort_value)
                    elif key == "monotonic":
                        sort_value = (
                            record.get("monotonic_us")
                            if isinstance(record.get("monotonic_us"), int)
                            else -1
                        )
                        item = NumericTableWidgetItem(str(value), sort_value)
                    elif key == "priority":
                        sort_value = (
                            record.get("priority_code")
                            if isinstance(record.get("priority_code"), int)
                            else 99
                        )
                        item = NumericTableWidgetItem(str(value), sort_value)
                    elif key == "facility":
                        sort_value = (
                            record.get("facility_code")
                            if isinstance(record.get("facility_code"), int)
                            else 99
                        )
                        item = NumericTableWidgetItem(str(value), sort_value)
                    else:
                        item = QTableWidgetItem(str(value))

                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(
                            Qt.AlignmentFlag.AlignRight
                            | Qt.AlignmentFlag.AlignVCenter
                        )
                    if record.get("access") == "Privileged Helper":
                        item.setForeground(QBrush(QColor(self.PRIVILEGED_DATA)))
                        item.setToolTip(
                            "Visible through the active privileged read-only /dev/kmsg collector"
                        )
                    self.table.setItem(row_index, column_index, item)

            self.table.setSortingEnabled(True)
        finally:
            self.table.blockSignals(blocked)

        self._synchronize_details_after_rebuild(visible)

        if query or priority or facility:
            self.filter_label.setText(
                f"(Showing {len(visible):,} of {len(self._records):,} records)"
            )
        else:
            self.filter_label.clear()

    def _selection_changed(self):
        row = self.table.currentRow()
        if row < 0:
            self.details.clear()
            return
        item = self.table.item(row, 0)
        record = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(record, dict):
            self.details.clear()
            return
        self._render_record_details(record)

    def _reset_details_to_top(self):
        cursor = self.details.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.details.setTextCursor(cursor)
        self.details.verticalScrollBar().setValue(0)

    def _render_record_details(self, record):
        self.details.setPlainText(self._record_details_text(record))
        self._reset_details_to_top()

    @staticmethod
    def _record_details_text(record):
        lines = ["--- /dev/kmsg Record Header ---"]

        def add(label, value):
            if value not in (None, "", []):
                lines.append(f"{label}: {value}")

        add("Syslog Prefix", record.get("syslog_prefix"))
        add("Priority Code", record.get("priority_code"))
        add("Priority", record.get("priority"))
        add("Facility Code", record.get("facility_code"))
        add("Facility", record.get("facility"))
        add("Sequence", record.get("sequence_display"))
        add("Monotonic Timestamp (µs)", record.get("monotonic_us"))
        add("Monotonic Time", record.get("monotonic"))
        add("Flags", record.get("flags"))
        add("Fragment", record.get("fragment"))

        extensions = list(record.get("header_extensions") or [])
        if extensions:
            lines.extend(["", "--- Optional Header Fields ---"])
            for index, value in enumerate(extensions, start=1):
                lines.append(f"Header Field {index}: {value}")

        if record.get("caller"):
            lines.extend(["", "--- PRINTK_CALLER ---"])
            add("Caller", record.get("caller"))
            add("Caller Type", record.get("caller_type"))
            add("Caller ID", record.get("caller_id"))

        context_entries = list(record.get("context_entries") or [])
        if context_entries:
            lines.extend(["", "--- Machine-readable Context ---"])
            counts = {}
            free_line = 0
            for entry in context_entries:
                key = str(entry.get("key") or "")
                value = str(entry.get("value") or "")
                if key:
                    counts[key] = counts.get(key, 0) + 1
                    label = key if counts[key] == 1 else f"{key} [{counts[key]}]"
                    lines.append(f"{label}: {value}")
                else:
                    free_line += 1
                    lines.append(f"Context Line {free_line}: {entry.get('line', '')}")

        lines.extend([
            "",
            "--- Message ---",
            f"Message: {_raw_one_line(record.get('message', ''))}",
        ])

        if record.get("parse_error"):
            lines.extend([
                "",
                "--- Parse Warning ---",
                f"Warning: {record.get('parse_error')}",
            ])

        lines.extend([
            "",
            "--- Raw Record ---",
            f"Header: {_raw_one_line(record.get('raw_header', ''))}",
            f"Record: {_raw_one_line(record.get('raw_record', ''))}",
            "",
            "--- Acquisition ---",
            f"Interface: {record.get('interface', KMSG_PATH)}",
            f"Access: {record.get('access', 'Standard access')}",
        ])
        return "\n".join(lines)

    def metadata_details_for_export(self, record):
        return self._record_details_text(record)

    @staticmethod
    def _exportable_record(record):
        item = dict(record)
        item["header_extensions_display"] = " | ".join(
            str(value) for value in (record.get("header_extensions") or [])
        )
        item["context_tags_display"] = " | ".join(
            f"{key}={value}" for key, value in (record.get("context_tags") or [])
        )
        return item

    def sources_report(self):
        lines = [
            "Kernel Ring Buffer",
            f"  {KMSG_PATH}",
        ]
        if self._source_status:
            status = self._source_status
            lines.extend([
                "",
                "Last Scan",
                "---------",
                f"{status.get('name')}: {status.get('state')}"
                + (
                    f" — {status.get('count', 0):,} record(s)"
                    if status.get("count")
                    else ""
                ),
            ])
            detail = str(status.get("detail") or "").strip()
            if detail:
                lines.append(f"  {detail}")
        return "\n".join(lines)

    def show_options(self, initial_tab=0):
        dialog = KernelRingBufferOptionsDialog(self, initial_tab=initial_tab)
        dialog.exec()
        self._update_privilege_ui(force=True)

    def _invalidate_for_access_change(self, message):
        self._records = []
        self._visible_records = []
        self._source_status = None
        self._has_scanned = False
        self.table.setRowCount(0)
        self.details.clear()
        self._rebuild_facility_filter()
        self._update_counter()
        self.filter_label.clear()
        self.set_status(message)

    def _apply_access_theme(self):
        if self.privilege.enabled:
            # Exact SELinux privileged metadata/status palette.
            self.set_theme_colors(
                "#1e1e1e",
                "#dcdcdc",
                "#f2d18b",
                "#e5bd70",
                "#3a2d13",
                "#f2d18b",
            )
        else:
            self.set_theme_colors(
                "#1e1e1e",
                "#dcdcdc",
                "#4ec9b0",
                "#ce9178",
                "#252526",
                "#dcdcdc",
            )

    def toggle_privileged(self):
        if self.privilege.state == "on":
            self.privilege.stop()
            self._update_privilege_ui(force=True)
            return
        if self.privilege.state == "connecting":
            return

        ok, why = self.privilege.availability()
        if not ok:
            self._update_privilege_ui(force=True)
            dialog = KernelRingBufferOptionsDialog(self, initial_tab=1)
            dialog.helper_access_label.setText(f"Privileged access: Unavailable — {why}")
            dialog.exec()
            self._update_privilege_ui(force=True)
            return

        self.privilege.start_async()
        self._update_privilege_ui(force=True)

    def _update_privilege_ui(self, force=False):
        state = self.privilege.state
        changed = force or state != self._last_priv_state

        if changed:
            previous = self._last_priv_state
            self._last_priv_state = state
            self._apply_access_theme()

            if state == "on" and self.privilege.enabled and previous != "on":
                self._invalidate_for_access_change(
                    "Privileged access active — current dataset cleared. Press Scan to read /dev/kmsg through the helper."
                )
            elif previous == "on" and state != "on":
                self._invalidate_for_access_change(
                    "Privileged access ended — privileged dataset cleared. Press Scan for ordinary /dev/kmsg access."
                )

        if state == "on" and self.privilege.enabled:
            self.priv_button.setText("Privileged: On")
            self.priv_button.setEnabled(True)
            self.priv_button.setStyleSheet(self.PRIVILEGE_ACTIVE_QSS)
        elif state == "connecting":
            self.priv_button.setText("Privileged: Authorizing…")
            self.priv_button.setEnabled(False)
            self.priv_button.setStyleSheet("")
        elif state == "error":
            self.priv_button.setText("Privileged: Off")
            self.priv_button.setEnabled(True)
            self.priv_button.setStyleSheet("")
        else:
            self.priv_button.setText("Privileged: Off")
            self.priv_button.setEnabled(True)
            self.priv_button.setStyleSheet("")

    def _end_privileged_for_deactivation(self, reason):
        active_or_connecting = bool(
            self.privilege.enabled
            or self.privilege.state in {"on", "connecting"}
        )
        if not active_or_connecting:
            return
        self.privilege.stop()
        self._update_privilege_ui(force=True)
        self.set_status(str(reason))

    def set_applet_active(self, active):
        """Suite lifecycle hook: privileged access never survives applet changes."""
        self._applet_active = bool(active)
        if not self._applet_active:
            self._end_privileged_for_deactivation(
                "Privileged access ended because Kernel Ring Buffer is no longer the active applet."
            )
        else:
            self._update_privilege_ui(force=True)

    def hideEvent(self, event):
        # QStackedWidget/page changes hide inactive applets. This is the
        # defensive fallback for hosts that do not call set_applet_active().
        if not self._shutting_down:
            self._end_privileged_for_deactivation(
                "Privileged access ended because Kernel Ring Buffer is no longer visible."
            )
        super().hideEvent(event)

    def shutdown(self):
        self._shutting_down = True
        if hasattr(self, "_priv_timer"):
            self._priv_timer.stop()
        self.privilege.stop()

    def _settings(self):
        return QSettings("brunonlinespace", "Kernel Ring Buffer")

    def _load_display_preferences(self):
        settings = self._settings()
        orientation = str(
            settings.value("details_orientation", "horizontal") or "horizontal"
        ).lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"

        metadata_value = settings.value("metadata_panel_visible", True)
        if isinstance(metadata_value, str):
            metadata_visible = metadata_value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            metadata_visible = bool(metadata_value)

        self.set_details_orientation(orientation, persist=False)
        self.set_metadata_panel_visible(metadata_visible, persist=False)

    def _setup_shortcuts(self):
        self._shortcuts = []

        def add_shortcut(sequence, handler):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(handler)
            self._shortcuts.append(shortcut)
            return shortcut

        add_shortcut("F3", self._shortcut_toggle_metadata)
        add_shortcut("Ctrl+L", self._shortcut_toggle_layout)
        add_shortcut("Ctrl+/", self.show_options)
        add_shortcut("Shift+F5", self._shortcut_repeat_scan)

        for value in range(8):
            add_shortcut(
                f"Ctrl+{value}",
                lambda value=value: self._shortcut_set_priority(str(value)),
            )
        add_shortcut("Ctrl+A", lambda: self._shortcut_set_priority(""))
        add_shortcut(
            "Ctrl+N",
            lambda: self._shortcut_set_priority("__not_reported__"),
        )

    def _shortcut_set_priority(self, value):
        index = self.priority_combo.findData(value)
        if index < 0:
            return
        self.priority_combo.setCurrentIndex(index)
        if value == "":
            label = "All"
        elif value == "__not_reported__":
            label = "Not reported"
        else:
            label = _priority_display(int(value))
        self.set_status(f"Priority filter: {label}.")

    def _shortcut_toggle_metadata(self):
        self.toggle_metadata_panel()
        self.set_status(
            "Metadata Details panel shown."
            if self.metadata_panel_visible
            else "Metadata Details panel hidden."
        )

    def _shortcut_toggle_layout(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(target, persist=True)
        self.set_status(
            "Metadata Details layout set to Vertical."
            if target == "vertical"
            else "Metadata Details layout set to Horizontal."
        )

    def _shortcut_repeat_scan(self):
        self.set_status("Repeating kernel ring scan...")
        self.scan()

    def set_metadata_panel_visible(self, visible, *, persist=True):
        visible = bool(visible)
        self.metadata_panel_visible = visible
        panel = self.splitter.widget(1)
        if panel is not None:
            panel.setVisible(visible)
        if visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            settings = self._settings()
            settings.setValue("metadata_panel_visible", visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation

        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None

        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([470, 340])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([810, 470])

        if persist:
            settings = self._settings()
            settings.setValue("details_orientation", orientation)
            settings.sync()

    def export_current(self):
        if not self._has_scanned:
            QMessageBox.information(
                self,
                "Export",
                "Kernel ring records have not been scanned yet.",
            )
            return

        records = [self._exportable_record(record) for record in self._records]
        path = export_records_dialog(
            self,
            APPLET_NAME,
            records,
            columns=[
                ("sequence_display", "Sequence"),
                ("monotonic", "Monotonic Time"),
                ("monotonic_us", "Monotonic Timestamp (µs)"),
                ("priority", "Priority"),
                ("facility", "Facility"),
                ("flags", "Flags"),
                ("caller", "Caller"),
                ("subsystem", "Subsystem"),
                ("device", "Device"),
                ("message", "Message"),
                ("header_extensions_display", "Optional Header Fields"),
                ("context_tags_display", "Machine-readable Context"),
                ("access", "Access"),
                ("raw_record", "Raw /dev/kmsg Record"),
            ],
            sections={"Source": KMSG_PATH},
        )
        if path:
            self.set_status(f"Exported kernel ring records to {path}")


def create_applet(parent=None):
    return KernelRingBufferInspector(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName("linspectacles")

    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))

    app.setStyleSheet(STANDALONE_STYLESHEET)

    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1480, 860)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
