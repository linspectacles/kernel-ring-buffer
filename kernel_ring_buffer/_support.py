#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspector Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

import csv
import io
import json
import re
from pathlib import Path

try:
    from packaging.version import parse as parse_version
except ImportError:
    def parse_version(value):
        return str(value).lower()

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSplitter,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget
)

STANDALONE_STYLESHEET = r"""
QMainWindow, QWidget { background-color: #1e1e1e; color: #dcdcdc; font-family: "Segoe UI", Ubuntu, sans-serif; font-size: 10pt; }
QTabWidget::pane { border: 1px solid #333333; background-color: #1e1e1e; }
QTabBar::tab { background-color: #2d2d2d; color: #aaaaaa; padding: 8px 16px; border: 1px solid #333333; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px; }
QTabBar::tab:selected { background-color: #007acc; color: #ffffff; font-weight: bold; }
QTabBar::tab:hover:!selected { background-color: #3e3e42; color: #ffffff; }
QGroupBox { border: 1px solid #333333; border-radius: 6px; margin-top: 6px; padding-top: 10px; background-color: #252526; }
QLineEdit { background-color: #333333; color: #ffffff; border: 1px solid #454545; border-radius: 4px; padding: 4px 8px; selection-background-color: #007acc; }
QLineEdit:focus { border: 1px solid #007acc; }
QTableWidget { background-color: #1e1e1e; alternate-background-color: #252526; color: #dcdcdc; gridline-color: #2d2d2d; border: 1px solid #333333; border-radius: 4px; }
QTableWidget::item:selected { background-color: #094771; color: #ffffff; }
QHeaderView::section { background-color: #2d2d2d; color: #ffffff; padding: 5px; border: 1px solid #333333; font-weight: bold; }
QPushButton { background-color: #333333; color: #ffffff; border: 1px solid #454545; border-radius: 3px; padding: 4px 8px; }
QPushButton:hover { background-color: #007acc; border-color: #007acc; }
QPushButton:pressed { background-color: #005999; }
QSplitter::handle { background-color: #2d2d2d; height: 3px; }
QScrollBar:vertical, QScrollBar:horizontal { background: #1e1e1e; border: none; width: 10px; height: 10px; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background: #424242; border-radius: 5px; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover { background: #686868; }
"""


def default_metadata_font():
    font = QFont("Monospace")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSize(10)
    return font


def metadata_font_from_string(serialized):
    if serialized:
        font = QFont()
        try:
            if font.fromString(str(serialized)):
                return font
        except Exception:
            pass
    return default_metadata_font()


def metadata_font_qss(font):
    family = font.family().replace("\\", "\\\\").replace('"', '\\"')
    size = font.pointSizeF() if font.pointSizeF() > 0 else 10.0
    try:
        raw_weight = font.weight()
        weight = int(getattr(raw_weight, "value", raw_weight))
    except Exception:
        weight = 400
    style = "italic" if font.italic() else "normal"
    return (
        f'font-family: "{family}"; font-size: {size:g}pt; '
        f'font-weight: {weight}; font-style: {style};'
    )


def apply_metadata_font(text_edit, serialized=""):
    """Apply a host-selected metadata font to the widget and its document."""
    font = metadata_font_from_string(serialized)
    text_edit.setFont(font)
    text_edit.document().setDefaultFont(font)
    text_edit.setCurrentFont(font)
    return font


class NumericTableWidgetItem(QTableWidgetItem):
    def __init__(self, text, raw_val=0):
        super().__init__(text)
        self.raw_val = raw_val

    def __lt__(self, other):
        if isinstance(other, NumericTableWidgetItem):
            return self.raw_val < other.raw_val
        return super().__lt__(other)


class MetadataHighlighter(QSyntaxHighlighter):
    """Colour key/value metadata without tying colours to inserted text."""

    def __init__(self, document):
        super().__init__(document)
        self.key_color = QColor("#4ec9b0")
        self.value_color = QColor("#ce9178")
        self.heading_color = QColor("#dcdcdc")

    def set_colors(self, key_color, value_color, heading_color):
        self.key_color = QColor(key_color)
        self.value_color = QColor(value_color)
        self.heading_color = QColor(heading_color)
        self.rehighlight()

    def highlightBlock(self, text):
        if not text:
            return

        if text.startswith("---"):
            heading = QTextCharFormat()
            heading.setForeground(self.key_color)
            heading.setFontWeight(QFont.Weight.Bold.value)
            self.setFormat(0, len(text), heading)
            return

        colon = text.find(":")
        if colon > 0:
            key_format = QTextCharFormat()
            key_format.setForeground(self.key_color)
            key_format.setFontWeight(QFont.Weight.Bold.value)
            self.setFormat(0, colon + 1, key_format)

            if colon + 1 < len(text):
                value_format = QTextCharFormat()
                value_format.setForeground(self.value_color)
                self.setFormat(colon + 1, len(text) - colon - 1, value_format)


class ColumnVisibilityController:
    """Right-click header menu for persistent per-applet column visibility."""

    def __init__(self, table, columns, status_callback=None):
        self.table = table
        self.columns = list(columns)
        self.status_callback = status_callback
        self._hidden = set()
        self._changed_callback = None
        header = self.table.horizontalHeader()
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_menu)
        self._update_resize_modes()

    def set_changed_callback(self, callback):
        self._changed_callback = callback if callable(callback) else None

    def hidden_columns(self):
        return [column[0] for column in self.columns if column[0] in self._hidden]

    def apply_hidden(self, column_ids):
        known = {column[0] for column in self.columns}
        hidden = {str(item) for item in (column_ids or []) if str(item) in known}
        if len(hidden) >= len(self.columns) and self.columns:
            hidden.discard(self.columns[0][0])
        self._hidden = hidden
        for index, (column_id, *_rest) in enumerate(self.columns):
            self.table.setColumnHidden(index, column_id in hidden)
        self._update_resize_modes()

    def _visible_count(self):
        return sum(1 for i in range(len(self.columns)) if not self.table.isColumnHidden(i))

    def _set_visible(self, index, visible):
        if not 0 <= index < len(self.columns):
            return
        column_id = self.columns[index][0]
        if not visible and self._visible_count() <= 1:
            if callable(self.status_callback):
                self.status_callback("At least one column must remain visible.")
            return

        self.table.setColumnHidden(index, not visible)
        if visible:
            self._hidden.discard(column_id)
        else:
            self._hidden.add(column_id)
        self._update_resize_modes()
        if self._changed_callback:
            self._changed_callback(self.hidden_columns())

    def _show_menu(self, pos):
        menu = QMenu(self.table)
        for index, (_column_id, label, *_rest) in enumerate(self.columns):
            action = menu.addAction(str(label))
            action.setCheckable(True)
            action.setChecked(not self.table.isColumnHidden(index))
            action.triggered.connect(
                lambda checked, column_index=index: self._set_visible(column_index, checked)
            )
        menu.exec(self.table.horizontalHeader().mapToGlobal(pos))

    def _update_resize_modes(self):
        header = self.table.horizontalHeader()
        visible = [i for i in range(len(self.columns)) if not self.table.isColumnHidden(i)]
        if not visible:
            return
        last_visible = visible[-1]
        for index in visible:
            header.setSectionResizeMode(
                index,
                QHeaderView.ResizeMode.Stretch
                if index == last_visible
                else QHeaderView.ResizeMode.Interactive,
            )


def _safe_scalar(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return None


def _friendly_label(key):
    return str(key).replace("_", " ").strip().title()


def _export_schema(records, columns=None):
    records = list(records or [])
    labels = {}
    order = []
    for column in columns or []:
        key = str(column[0])
        label = str(column[1]) if len(column) > 1 else _friendly_label(key)
        labels[key] = label
        if key not in order:
            order.append(key)

    for record in records:
        if not isinstance(record, dict):
            continue
        for key, value in record.items():
            if str(key).startswith("_") or _safe_scalar(value) is None:
                continue
            key = str(key)
            if key not in labels:
                labels[key] = _friendly_label(key)
            if key not in order:
                order.append(key)

    clean = []
    for record in records:
        if not isinstance(record, dict):
            continue
        clean_record = {}
        for key in order:
            scalar = _safe_scalar(record.get(key, ""))
            if scalar is not None:
                clean_record[key] = scalar
        clean.append(clean_record)
    return order, labels, clean


def _slug(text):
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", str(text).strip()).strip("-")
    return value.lower() or "linspectacles-export"


def _plain_text_export(title, order, labels, records, sections):
    lines = [f"LinSpectacles - {title}", "=" * max(12, len(title) + 12), ""]
    for section_title, section_text in (sections or {}).items():
        lines.extend([str(section_title), "-" * len(str(section_title)), str(section_text).rstrip(), ""])
    lines.append(f"Items: {len(records)}")
    lines.append("")
    for index, record in enumerate(records, start=1):
        lines.append(f"Item {index}")
        lines.append("-" * (5 + len(str(index))))
        for key in order:
            if key in record:
                lines.append(f"{labels.get(key, _friendly_label(key))}: {record.get(key, '')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _csv_export(order, labels, records):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow([labels.get(key, _friendly_label(key)) for key in order])
    for record in records:
        writer.writerow([record.get(key, "") for key in order])
    return stream.getvalue()


def _markdown_export(title, order, labels, records, sections):
    lines = [f"# {title}", ""]
    for section_title, section_text in (sections or {}).items():
        lines.extend([f"## {section_title}", "", str(section_text).rstrip(), ""])
    if order:
        lines.append("| " + " | ".join(labels.get(key, _friendly_label(key)) for key in order) + " |")
        lines.append("| " + " | ".join("---" for _ in order) + " |")
        for record in records:
            row = []
            for key in order:
                value = str(record.get(key, "")).replace("|", "\\|").replace("\n", "<br>")
                row.append(value)
            lines.append("| " + " | ".join(row) + " |")
    else:
        lines.append("No items.")
    return "\n".join(lines).rstrip() + "\n"


def export_records_dialog(parent, title, records, columns=None, sections=None):
    """Export already-collected applet data. Plain text is the default format."""
    order, labels, clean_records = _export_schema(records, columns)
    filters = (
        "Plain Text (*.txt);;"
        "CSV (*.csv);;"
        "JSON (*.json);;"
        "Markdown (*.md)"
    )
    default_name = f"{_slug(title)}.txt"
    filename, selected_filter = QFileDialog.getSaveFileName(
        parent,
        f"Export {title}",
        default_name,
        filters,
        "Plain Text (*.txt)",
    )
    if not filename:
        return None

    selected_filter = selected_filter or "Plain Text (*.txt)"
    if selected_filter.startswith("CSV"):
        extension = ".csv"
        text = _csv_export(order, labels, clean_records)
    elif selected_filter.startswith("JSON"):
        extension = ".json"
        payload = {"applet": title, "items": clean_records}
        if sections:
            payload["sections"] = {str(k): str(v) for k, v in sections.items()}
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    elif selected_filter.startswith("Markdown"):
        extension = ".md"
        text = _markdown_export(title, order, labels, clean_records, sections)
    else:
        extension = ".txt"
        text = _plain_text_export(title, order, labels, clean_records, sections)

    path = Path(filename).expanduser()
    if not path.suffix:
        path = path.with_suffix(extension)
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        QMessageBox.critical(parent, "Export", f"Could not write the export:\n{exc}")
        return None
    return path


class BaseInspectorTab(QWidget):
    """Shared table/filter/metadata UI used by all inspector tabs."""

    NUMERIC_COLUMNS = {"size"}

    def __init__(self, total_label_text, columns, categories, parent=None):
        super().__init__(parent)
        self.modules_data = []
        self.total_label_text = total_label_text
        self.export_title = total_label_text[6:] if total_label_text.startswith("Total ") else total_label_text
        self.columns = columns
        self.categories = categories
        self._sort_reverse = {}

        self._key_color = QColor("#4ec9b0")
        self._value_color = QColor("#ce9178")
        self._heading_color = QColor("#dcdcdc")
        self._text_bg = "#1e1e1e"
        self._text_fg = "#dcdcdc"
        self._metadata_font = default_metadata_font()

        self.setup_ui()

    def setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        dash_layout = QHBoxLayout()
        self.dash_layout = dash_layout
        self.stats_label = QLabel(f"{self.total_label_text}: 0")
        stats_font = self.stats_label.font()
        stats_font.setBold(True)
        stats_font.setPointSize(max(stats_font.pointSize(), 11))
        self.stats_label.setFont(stats_font)
        dash_layout.addWidget(self.stats_label)
        dash_layout.addStretch(1)

        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.load_modules)
        dash_layout.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Export...")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_current_data)
        dash_layout.addWidget(self.export_btn)
        root.addLayout(dash_layout)

        filter_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-weight: 600;")
        filter_layout.addWidget(search_label)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search items...")
        self.search_entry.setMaximumWidth(280)
        self.search_entry.textChanged.connect(self.filter_modules)
        filter_layout.addWidget(self.search_entry)

        self.category_label = QLabel("Category:")
        self.category_label.setStyleSheet("font-weight: 600;")
        filter_layout.addWidget(self.category_label)

        self.category_dropdown = QComboBox()
        self.category_dropdown.addItems(self.categories)
        self.category_dropdown.setMinimumWidth(190)
        self.category_dropdown.currentTextChanged.connect(self.filter_modules)
        filter_layout.addWidget(self.category_dropdown)

        self.filter_status_lbl = QLabel("")
        filter_font = self.filter_status_lbl.font()
        filter_font.setItalic(True)
        self.filter_status_lbl.setFont(filter_font)
        filter_layout.addWidget(self.filter_status_lbl)
        filter_layout.addStretch(1)
        root.addLayout(filter_layout)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(self.splitter, 1)

        self.table = QTableWidget(0, len(self.columns))
        self.table.setHorizontalHeaderLabels([column[1] for column in self.columns])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self.on_module_select)
        self.table.horizontalHeader().sectionClicked.connect(self.sort_by_section)

        header = self.table.horizontalHeader()
        for index, (_column_id, _label, width, _alignment) in enumerate(self.columns):
            self.table.setColumnWidth(index, width)

        self.column_visibility = ColumnVisibilityController(
            self.table, self.columns, self.set_status
        )
        self.splitter.addWidget(self.table)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 0, 0, 0)
        metadata_label = QLabel("Metadata Details")
        metadata_font = metadata_label.font()
        metadata_font.setBold(True)
        metadata_font.setPointSize(max(metadata_font.pointSize(), 11))
        metadata_label.setFont(metadata_font)
        right_layout.addWidget(metadata_label)

        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self._metadata_font = apply_metadata_font(self.info_text)
        self.info_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.metadata_highlighter = MetadataHighlighter(self.info_text.document())
        right_layout.addWidget(self.info_text, 1)
        self.splitter.addWidget(right_panel)
        self.splitter.setSizes([480, 700])

        self.status_lbl = QLabel("Ready - Select an item to inspect properties.")
        status_font = self.status_lbl.font()
        status_font.setItalic(True)
        self.status_lbl.setFont(status_font)
        self.status_lbl.setFrameShape(QFrame.Shape.NoFrame)
        self.status_lbl.setContentsMargins(4, 4, 4, 4)
        root.addWidget(self.status_lbl)

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        settings = settings or {}
        self._metadata_font = apply_metadata_font(
            self.info_text, settings.get("metadata_font", "")
        )
        self._update_info_style()
        self.column_visibility.set_changed_callback(column_visibility_callback)
        self.column_visibility.apply_hidden(settings.get("hidden_columns", []))

    def set_theme_colors(
        self, text_bg, text_fg, key_fg, value_fg, status_bg, status_fg
    ):
        self._key_color = QColor(key_fg)
        self._value_color = QColor(value_fg)
        self._heading_color = QColor(text_fg)
        self._text_bg = text_bg
        self._text_fg = text_fg

        self._update_info_style()
        self.metadata_highlighter.set_colors(key_fg, value_fg, text_fg)
        self.status_lbl.setStyleSheet(
            f"QLabel {{ background: {status_bg}; color: {status_fg}; padding: 4px; }}"
        )
        self.filter_modules()

    def _update_info_style(self):
        self.info_text.setStyleSheet(
            "QTextEdit { "
            f"background: {self._text_bg}; color: {self._text_fg}; "
            "border: 1px solid #666; "
            f"{metadata_font_qss(self._metadata_font)} "
            "}"
        )

    def style_table_item(self, item, column_id, record):
        return

    def clear_info(self):
        self.info_text.clear()

    def append_info(self, text, style="value"):
        cursor = self.info_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(str(text))
        self.info_text.setTextCursor(cursor)

    def append_key_value(self, key, value):
        self.append_info(f"{key}: ", "key")
        self.append_info(f"{value}\n", "value")

    def current_record(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def filter_modules(self, *_):
        query = self.search_entry.text().strip().lower()
        selected_category = self.category_dropdown.currentText()

        matches = []
        for mod in self.modules_data:
            match_category = (
                selected_category == "All Categories"
                or mod.get("category") == selected_category
            )
            match_query = not query or any(
                query in str(value).lower() for value in mod.values()
            )
            if match_category and match_query:
                matches.append(mod)

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(matches))

        for row, mod in enumerate(matches):
            for column_index, (column_id, _label, _width, alignment) in enumerate(self.columns):
                value = mod.get(column_id, "")
                if column_id in self.NUMERIC_COLUMNS and isinstance(value, int):
                    display = f"{value:,}"
                else:
                    display = str(value)

                item = QTableWidgetItem(display)
                if column_index == 0:
                    item.setData(Qt.ItemDataRole.UserRole, mod)
                if alignment == "right":
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                    )
                else:
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                    )
                self.style_table_item(item, column_id, mod)
                self.table.setItem(row, column_index, item)

        self.export_btn.setEnabled(bool(self.modules_data))
        if query or selected_category != "All Categories":
            self.filter_status_lbl.setText(
                f"(Showing {len(matches)} of {len(self.modules_data)} items)"
            )
        else:
            self.filter_status_lbl.clear()

    def sort_by_section(self, section):
        if not (0 <= section < len(self.columns)):
            return
        self.sort_by(self.columns[section][0])

    def sort_by(self, column_id):
        reverse = self._sort_reverse.get(column_id, False)

        if column_id in self.NUMERIC_COLUMNS:
            key_func = lambda item: item.get(column_id, 0)
        elif column_id == "version":
            key_func = lambda item: parse_version(str(item.get(column_id, "")))
        else:
            key_func = lambda item: str(item.get(column_id, "")).lower()

        try:
            self.modules_data.sort(key=key_func, reverse=reverse)
        except Exception:
            self.modules_data.sort(
                key=lambda item: str(item.get(column_id, "")).lower(),
                reverse=reverse,
            )

        self._sort_reverse[column_id] = not reverse
        self.filter_modules()

    def get_export_records(self):
        return list(self.modules_data)

    def export_current_data(self):
        records = self.get_export_records()
        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export yet.")
            return
        path = export_records_dialog(
            self, self.export_title, records, columns=self.columns
        )
        if path is not None:
            self.set_status(f"Exported data to {path}")

    def set_status(self, text):
        self.status_lbl.setText(text)

    def show_error(self, title, text):
        QMessageBox.critical(self, title, text)

    def load_modules(self):
        raise NotImplementedError

    def on_module_select(self):
        raise NotImplementedError
