"""
Cryptid - desktop app to encrypt / decrypt files and folders before they go to the cloud.

Run:   python cryptid_gui.py
Build: build_exe.bat   (creates dist\\Cryptid\\Cryptid.exe)
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import sys
import tempfile
import threading
import time

from cryptography.exceptions import InvalidTag
from PySide6.QtCore import QPoint, QPointF, QRectF, QSettings, QSize, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QPainter, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QScrollArea, QSizePolicy, QStackedLayout, QToolButton, QVBoxLayout,
    QWidget,
)

import cryptid_core as core

APP_NAME = "Cryptid"

# Steel and brass: a vault, not a dashboard. The accent changes with the mode.
C = dict(bg="#1a2230", panel="#202a3a", field="#2a3649", line="#33415a",
         text="#e8edf5", muted="#92a2b8", ok="#74d3a0", err="#f0786d", on_accent="#1a2230")
ACCENTS = {"encrypt": "#e0ae45", "decrypt": "#4cc3b4", "verify": "#7fa6e8"}
THEME = {"accent": ACCENTS["encrypt"]}


def _rgba(hex_color: str, alpha: int) -> str:
    h = hex_color.lstrip("#")
    return f"rgba({int(h[0:2], 16)}, {int(h[2:4], 16)}, {int(h[4:6], 16)}, {alpha})"


def _check_icon() -> str:
    """Draws the tick used inside checked checkboxes (QSS needs an image file)."""
    path = os.path.join(tempfile.gettempdir(), "cryptid_check.png")
    pm = QPixmap(32, 32)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(C["on_accent"]), 4.2)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPolyline([QPointF(8, 17), QPointF(14, 23), QPointF(24, 10)])
    p.end()
    pm.save(path, "PNG")
    return path.replace("\\", "/")


def build_qss(accent: str) -> str:
    tick = _check_icon()
    return f"""
* {{ font-family: "Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
     font-size: 13px; color: {C['text']}; }}
QWidget#root {{ background: {C['bg']}; }}
QLabel {{ background: transparent; }}
QLabel#title {{ font-size: 24px; font-weight: 600; }}
QLabel#muted {{ color: {C['muted']}; }}
QLabel#small {{ color: {C['muted']}; font-size: 12px; }}
QLabel#section {{ font-size: 14px; font-weight: 600; }}
QLabel#bigdrop {{ font-size: 17px; font-weight: 600; }}
QPushButton {{ background: {C['field']}; border: 1px solid {C['line']}; border-radius: 8px; padding: 7px 14px; }}
QPushButton:hover {{ border-color: {accent}; }}
QPushButton:disabled {{ color: #66758c; border-color: {C['line']}; }}
QPushButton#primary {{ background: {accent}; color: {C['on_accent']}; border: none;
                       font-weight: 600; font-size: 14px; padding: 12px; }}
QPushButton#primary:hover {{ background: {accent}; }}
QPushButton#primary:disabled {{ background: #3a465c; color: #8795ab; }}
QPushButton#danger {{ background: transparent; border: 1px solid {C['err']}; color: {C['err']};
                      font-weight: 600; font-size: 14px; padding: 12px; }}
QPushButton#danger:hover {{ background: #3a2a2f; }}
QPushButton#ghost {{ background: transparent; border: none; color: {C['muted']}; padding: 5px 8px; }}
QPushButton#ghost:hover {{ color: {C['text']}; }}
QPushButton#ghost:disabled {{ color: #55637a; }}
QPushButton[seg="true"] {{ background: transparent; border: none; border-radius: 7px;
                           padding: 8px 20px; color: {C['muted']}; font-weight: 600; font-size: 14px; }}
QPushButton[seg="true"]:hover {{ color: {C['text']}; }}
QPushButton[seg="true"]:checked {{ background: {accent}; color: {C['on_accent']}; }}
QFrame#segbar {{ background: {C['panel']}; border: 1px solid {C['line']}; border-radius: 10px; }}
QFrame#drop {{ background: {C['panel']}; border: 1px dashed {C['line']}; border-radius: 12px; }}
QFrame#drop[drag="true"] {{ border: 1px dashed {accent}; background: #253146; }}
QFrame#row {{ background: transparent; border: none; border-bottom: 1px solid {C['line']}; }}
QDialog {{ background: {C['bg']}; color: {C['text']}; }}
QFrame#pad {{ background: {C['panel']}; border: 1px dashed {accent}; border-radius: 12px; }}
QFrame#vline {{ background: {C['line']}; max-width: 1px; border: none; }}
QFrame#hline {{ background: {C['line']}; max-height: 1px; border: none; }}
QLineEdit, QComboBox {{ background: {C['field']}; border: 1px solid {C['line']}; border-radius: 8px;
                        padding: 7px 10px; selection-background-color: {accent}; selection-color: {C['on_accent']}; }}
QLineEdit, QComboBox {{ min-height: 20px; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {accent}; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{ background: {C['field']}; border: 1px solid {C['line']}; outline: none;
                               selection-background-color: {accent}; selection-color: {C['on_accent']}; padding: 4px; }}
QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid {C['line']}; background: {C['field']}; }}
QCheckBox::indicator:checked {{ background: {accent}; border-color: {accent}; image: url({tick}); }}
QCheckBox::indicator:disabled {{ background: #2a3447; border-color: #3a475d; }}
QCheckBox::indicator:checked:disabled {{ background: {_rgba(accent, 110)}; border-color: {_rgba(accent, 110)}; image: url({tick}); }}
QProgressBar {{ background: {C['field']}; border: none; border-radius: 2px; min-height: 4px; max-height: 4px; }}
QProgressBar::chunk {{ background: {accent}; border-radius: 2px; }}
QProgressBar#overall {{ min-height: 6px; max-height: 6px; border-radius: 3px; }}
QProgressBar#overall::chunk {{ border-radius: 3px; }}
QListWidget {{ background: transparent; border: none; outline: none; }}
QListWidget::item {{ background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {C['line']}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #46567a; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QPlainTextEdit#log {{ background: {C['panel']}; border: 1px solid {C['line']}; border-radius: 8px;
                      font-family: Consolas, "Cascadia Mono", monospace; font-size: 12px; color: {C['muted']}; padding: 6px; }}
QToolButton#x {{ background: transparent; border: none; color: {C['muted']}; padding: 6px; font-size: 14px; }}
QToolButton#x:hover {{ color: {C['err']}; }}
QToolButton#x:disabled {{ color: #4a566b; }}
QToolTip {{ background: {C['panel']}; color: {C['text']}; border: 1px solid {C['line']}; padding: 4px; }}
QMessageBox {{ background: {C['panel']}; }}
"""


# -- Small widgets -------------------------------------------------------------

class ElidedLabel(QLabel):
    """Single-line label that elides in the middle instead of forcing the layout wider."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full = text
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        super().setText(text)

    def setText(self, text: str):  # noqa: N802
        self._full = text
        super().setText(text)
        self.update()

    def minimumSizeHint(self):  # noqa: N802
        return QSize(10, super().minimumSizeHint().height())

    def paintEvent(self, _event):  # noqa: N802
        p = QPainter(self)
        p.setPen(self.palette().color(QPalette.ColorRole.WindowText))
        p.setFont(self.font())
        text = self.fontMetrics().elidedText(self._full, Qt.TextElideMode.ElideMiddle, self.width())
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, text)


class DropFrame(QFrame):
    dropped = Signal(list)

    def __init__(self):
        super().__init__()
        self.setObjectName("drop")
        self.setAcceptDrops(True)

    def _set_drag(self, on: bool):
        self.setProperty("drag", on)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e):  # noqa: N802
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._set_drag(True)

    def dragLeaveEvent(self, _e):  # noqa: N802
        self._set_drag(False)

    def dropEvent(self, e):  # noqa: N802
        self._set_drag(False)
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)
            e.acceptProposedAction()


class JobRow(QFrame):
    removed = Signal(object)

    def __init__(self, path: str, kind: str):
        super().__init__()
        self.setObjectName("row")
        self.path = path
        self.kind = kind
        icon = QLabel({"folder": "📁", "enc": "🔒"}.get(kind, "📄"))
        icon.setFixedWidth(34)
        icon.setStyleSheet("font-size: 22px;")
        self.name = ElidedLabel(os.path.basename(path.rstrip("\\/")) or path)
        self.name.setStyleSheet("font-weight: 600;")
        self.info = ElidedLabel(self._initial_info(path, kind))
        self.info.setObjectName("small")
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        self.status = QLabel("Ready")
        self.status.setObjectName("small")
        self.status.setMinimumWidth(130)
        self.status.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.x = QToolButton()
        self.x.setObjectName("x")
        self.x.setText("✕")
        self.x.setToolTip("Remove from the list")
        self.x.clicked.connect(lambda: self.removed.emit(self))

        mid = QVBoxLayout()
        mid.setSpacing(3)
        mid.addWidget(self.name)
        mid.addWidget(self.info)
        mid.addSpacing(2)
        mid.addWidget(self.bar)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 8, 8, 8)
        lay.setSpacing(10)
        lay.addWidget(icon)
        lay.addLayout(mid, 1)
        lay.addWidget(self.status)
        lay.addWidget(self.x)
        self.setToolTip(path)

    @staticmethod
    def _initial_info(path: str, kind: str) -> str:
        if kind == "folder":
            return f"Folder  ·  {os.path.dirname(path.rstrip(chr(92) + '/'))}"
        try:
            return f"{core.size_str(os.path.getsize(path))}  ·  {os.path.dirname(path)}"
        except OSError:
            return os.path.dirname(path)

    def set_state(self, state: str, text: str, frac: float, detail: str = ""):
        color = {"ready": C["muted"], "running": THEME["accent"], "ok": C["ok"], "error": C["err"],
                 "skipped": C["muted"], "cancelled": C["muted"]}[state]
        self.status.setStyleSheet(f"color: {color};")
        self.status.setText(text)
        self.bar.setValue(int(frac * 1000))
        if detail:
            self.info.setText(detail)
            self.setToolTip(f"{self.path}\n{detail}")

    def set_busy(self, busy: bool):
        self.x.setEnabled(not busy)

    def reset(self):
        self.set_state("ready", "Ready", 0.0)
        self.info.setText(self._initial_info(self.path, self.kind))
        self.setToolTip(self.path)


class Job:
    def __init__(self, path: str, kind: str, item: QListWidgetItem, row: JobRow):
        self.path, self.kind, self.item, self.row = path, kind, item, row


# -- Worker thread -------------------------------------------------------------

class Worker(QThread):
    row_update = Signal(int, str, float, str, str)   # index, state, fraction, status, detail
    log = Signal(str)
    summary = Signal(int, int, int, int)             # ok, failed, skipped, cancelled
    output_dir = Signal(str)

    def __init__(self, mode, paths, password, out_dir, opts, overwrite, known_ext=(core.DEFAULT_EXTENSION,),
                 keyfile=None):
        super().__init__()
        self.keyfile = keyfile
        self.mode, self.paths, self.password = mode, paths, password
        self.out_dir, self.opts, self.overwrite = out_dir, opts, overwrite
        self.known_ext = tuple(known_ext)
        self.cancel = threading.Event()

    def run(self):
        ok = failed = skipped = cancelled = 0
        bad_pw_streak = 0
        for i, path in enumerate(self.paths):
            name = os.path.basename(path.rstrip("\\/")) or path
            if self.cancel.is_set():
                self.row_update.emit(i, "cancelled", 0.0, "Cancelled", "")
                cancelled += 1
                continue
            if self.mode in ("decrypt", "verify") and ok == 0 and bad_pw_streak >= 3:
                self.row_update.emit(i, "skipped", 0.0, "Not tried",
                                     "Stopped: the password was wrong for the first 3 files.")
                skipped += 1
                continue

            def on_progress(frac, stage, i=i):
                no_pct = stage in ("Deriving key", "Tuning key settings", "Reading", "Removing original")
                text = stage if no_pct else f"{stage} {int(frac * 100)}%"
                self.row_update.emit(i, "running", frac, text, "")

            hooks = core.Hooks(self.cancel, on_progress, self.log.emit)
            self.row_update.emit(i, "running", 0.0, "Starting", "")
            try:
                if self.mode == "encrypt":
                    r = core.encrypt_path(path, self.out_dir, self.password, self.opts, hooks)
                    detail = f"{core.size_str(r.in_size)} → {core.size_str(r.out_size)}  ·  {os.path.basename(r.output)}"
                    if self.opts.keyfile:
                        detail += "  ·  password + key file"
                    tag = {"trashed": "original moved to the Trash", "deleted": "original deleted",
                           "wiped": "original overwritten and deleted", "partly removed": "⚠ original only partly removed"}.get(r.original)
                    if tag:
                        detail += "  ·  " + tag
                    kept = next((w for w in r.warnings if w.startswith("Original kept")), None)
                    if kept:
                        detail += "  ·  ⚠ " + kept.rstrip(".")
                elif self.mode == "verify":
                    r = core.verify_path(path, self.password, hooks, keyfile=self.keyfile)
                    what = f"{r.files} file{'s' if r.files != 1 else ''}  ·  " if r.is_folder else ""
                    detail = f"All data intact  ·  {what}{core.size_str(r.out_size)}"
                else:
                    r = core.decrypt_path(path, self.out_dir, self.password, self.overwrite, hooks, self.known_ext,
                                          keyfile=self.keyfile)
                    detail = f"Restored  ·  {os.path.basename(r.output.rstrip(chr(92) + '/'))}"
                for w in r.warnings:
                    self.log.emit(f"Warning ({name}): {w}")
                if self.mode == "verify":
                    self.log.emit(f"Verified: {name} ({detail})")
                else:
                    self.log.emit(f"Done: {name} → {r.output}")
                    self.output_dir.emit(os.path.dirname(r.output) if os.path.isfile(r.output) else r.output)
                self.row_update.emit(i, "ok", 1.0, "Verified" if self.mode == "verify" else "Done", detail)
                ok += 1
                bad_pw_streak = 0
            except core.Cancelled:
                self.row_update.emit(i, "cancelled", 0.0, "Cancelled", "")
                self.log.emit(f"Cancelled: {name}")
                cancelled += 1
            except core.Skipped as e:
                self.row_update.emit(i, "skipped", 0.0, "Skipped", str(e))
                self.log.emit(f"Skipped: {name} ({e})")
                skipped += 1
            except (core.LimitExceeded, core.FormatError) as e:
                self.row_update.emit(i, "error", 0.0, "Stopped", str(e))
                self.log.emit(f"Stopped: {name}: {e}")
                failed += 1
            except InvalidTag:
                if self.keyfile or (self.mode != "encrypt" and core.file_needs_keyfile(path)):
                    msg = "Wrong password or wrong key file, or the file is damaged or was modified."
                else:
                    msg = "Wrong password, or the file is damaged or was modified."
                self.row_update.emit(i, "error", 0.0, "Failed", msg)
                self.log.emit(f"Failed: {name}: {msg}")
                failed += 1
                bad_pw_streak += 1
            except Exception as e:  # noqa: BLE001
                self.row_update.emit(i, "error", 0.0, "Failed", str(e))
                self.log.emit(f"Failed: {name}: {e}")
                failed += 1
        self.password = ""
        self.summary.emit(ok, failed, skipped, cancelled)


# -- Create a key file ---------------------------------------------------------

class EntropyPad(QFrame):
    """Move the mouse over it: every movement feeds the random pool (like KeePass)."""

    def __init__(self, dialog):
        super().__init__()
        self._dlg = dialog
        self.setObjectName("pad")
        self.setMouseTracking(True)
        self.setMinimumHeight(150)
        self.setCursor(Qt.CursorShape.CrossCursor)
        self._trail: list = []
        self._last = None

    def mouseMoveEvent(self, e):
        pos = e.position().toPoint()
        if self._last is None or abs(pos.x() - self._last.x()) + abs(pos.y() - self._last.y()) >= 4:
            self._last = QPoint(pos)
            self._dlg.add_sample(struct.pack(">iiQ", pos.x(), pos.y(), time.perf_counter_ns()), 1)
            self._trail.append(QPoint(pos))
            del self._trail[:-70]
            self.update()
        super().mouseMoveEvent(e)

    def paintEvent(self, e):
        super().paintEvent(e)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        n = len(self._trail)
        for i, pt in enumerate(self._trail):
            col = QColor(THEME["accent"])
            col.setAlpha(int(25 + 200 * (i + 1) / max(n, 1)))
            p.setPen(QPen(Qt.PenStyle.NoPen))
            p.setBrush(QBrush(col))
            r = 2 + 4.0 * (i + 1) / max(n, 1)
            p.drawEllipse(QRectF(pt.x() - r, pt.y() - r, 2 * r, 2 * r))
        p.end()


class TypingEdit(QLineEdit):
    """Type anything: which keys and exactly when feeds the random pool."""

    def __init__(self, dialog):
        super().__init__()
        self._dlg = dialog

    def keyPressEvent(self, e):
        self._dlg.add_sample(struct.pack(">iQ", e.key(), time.perf_counter_ns()) + e.text().encode("utf-8", "replace"), 6)
        super().keyPressEvent(e)


class KeyfileDialog(QDialog):
    """Creates a unique key file. The OS random generator is always the base; what the user
    does here (mouse, keyboard) is mixed in on top, as in KeePass."""

    NEEDED = 1680         # points (4 x 420): a mouse movement is worth 1, a key press 6

    def __init__(self, parent=None, start_dir: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Create a key file")
        self.setModal(True)
        self.resize(520, 560)
        self._pool = hashlib.sha512(b"Cryptid-pad\x01" + os.urandom(32))
        self.points = 0
        self.start_dir = start_dir if os.path.isdir(start_dir or "") else os.path.expanduser("~")
        self.path = ""
        self.key_id = ""

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        intro = QLabel(
            "A key file is a second secret next to your password: to open the encrypted files you will need "
            "<b>both</b>. Make it unique by moving the mouse over the area below and typing random "
            "characters until the bar is full.")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        self.pad = EntropyPad(self)
        lay.addWidget(self.pad, 1)
        self.typing = TypingEdit(self)
        self.typing.setPlaceholderText("Type random characters here…")
        lay.addWidget(self.typing)
        self.bar = QProgressBar()
        self.bar.setRange(0, self.NEEDED)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        lay.addWidget(self.bar)
        self.msg = QLabel("")
        self.msg.setObjectName("small")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.backup_btn = QPushButton("Save a backup copy…")
        self.backup_btn.setVisible(False)
        self.backup_btn.clicked.connect(self.save_backup)
        self.create_btn = QPushButton("Create key file…")
        self.create_btn.setObjectName("primary")
        self.create_btn.setEnabled(False)
        self.create_btn.clicked.connect(self.on_create)
        self.use_btn = QPushButton("Use it")
        self.use_btn.setObjectName("primary")
        self.use_btn.setVisible(False)
        self.use_btn.clicked.connect(self.accept)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.backup_btn)
        row.addStretch(1)
        row.addWidget(self.create_btn)
        row.addWidget(self.use_btn)
        lay.addLayout(row)
        self._update_msg()

    def add_sample(self, data: bytes, weight: int):
        if self.path:           # already created
            return
        self._pool.update(data)
        self.points += weight
        self.bar.setValue(min(self.points, self.NEEDED))
        done = self.points >= self.NEEDED
        self.create_btn.setEnabled(done)
        self._update_msg()

    def _update_msg(self):
        if self.path:
            return
        if self.points >= self.NEEDED:
            self.msg.setText("Enough randomness collected. Now choose where to save the key file.")
        else:
            self.msg.setText(f"Collecting randomness… {min(100, self.points * 100 // self.NEEDED)}%  "
                             "(the computer's own random generator is always used as well)")

    def entropy(self) -> bytes:
        return self._pool.digest()

    def on_create(self):
        start = os.path.join(self.start_dir, f"Cryptid.{core.KEYFILE_EXTENSION}")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save the key file", start, f"Cryptid key file (*.{core.KEYFILE_EXTENSION})")
        if path:
            self.create_at(path)

    def create_at(self, path: str):
        path = os.path.normpath(path)
        if not os.path.splitext(path)[1]:
            path += "." + core.KEYFILE_EXTENSION
        try:
            self.key_id = core.create_keyfile(path, self.entropy())
        except (OSError, ValueError) as e:
            self.msg.setStyleSheet(f"color: {C['err']};")
            self.msg.setText(str(e))
            return
        self.path = path
        self.msg.setStyleSheet("")
        self.msg.setText(
            f"Created: {path}\nKey ID: {self.key_id}\n\n"
            "• Keep it somewhere else than your encrypted files (a USB stick, a password manager), "
            "otherwise it protects nothing.\n"
            "• Make a backup copy now. If this file is lost, the data it protects cannot be recovered.")
        self.create_btn.setVisible(False)
        self.pad.setEnabled(False)
        self.typing.setEnabled(False)
        self.backup_btn.setVisible(True)
        self.use_btn.setVisible(True)
        self.cancel_btn.setText("Close")

    def save_backup(self):
        name = os.path.basename(self.path)
        dest, _ = QFileDialog.getSaveFileName(
            self, "Save a backup copy somewhere else", os.path.join(os.path.dirname(self.path), "backup-" + name),
            f"Cryptid key file (*.{core.KEYFILE_EXTENSION})")
        if dest:
            self.copy_to(dest)

    def copy_to(self, dest: str):
        try:
            with open(self.path, "rb") as src, open(dest, "xb") as out:     # never overwrites
                out.write(src.read())
            os.chmod(dest, 0o600)
            self.msg.setStyleSheet("")
            self.msg.setText(self.msg.text() + f"\n\nBackup saved: {dest}")
        except OSError as e:
            self.msg.setStyleSheet(f"color: {C['err']};")
            self.msg.setText(f"Could not save the backup: {e.strerror or e}")


# -- Main window ---------------------------------------------------------------

def _combo(items, current=None):
    cb = QComboBox()
    for label, value in items:
        cb.addItem(label, value)
    if current is not None:
        idx = cb.findData(current)
        if idx >= 0:
            cb.setCurrentIndex(idx)
    cb.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    return cb


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("root")
        self.setWindowTitle(APP_NAME)
        self.resize(1060, 740)
        self.setMinimumSize(940, 600)
        self.settings = QSettings(APP_NAME, APP_NAME)
        self.mode = "encrypt"
        self.jobs: list[Job] = []
        self.worker: Worker | None = None
        s0 = self.settings
        legacy_folder, legacy_choice = s0.value("out_folder", "", str), s0.value("out", "same", str)
        self.out_folders = {m: s0.value(f"out_folder_{m}", legacy_folder, str) for m in ("encrypt", "decrypt")}
        self.out_choice = {m: s0.value(f"out_{m}", legacy_choice, str) for m in ("encrypt", "decrypt")}
        # Extensions used before (comma separated: QSettings turns one-item lists into plain strings).
        self.ext_history = [e for e in s0.value("ext_history", "", str).split(",") if e]
        self._ext_flash = ""
        self.row_frac: list[float] = []
        self.last_output_dir = ""

        self._build()
        self._load_settings()
        self.set_mode(self.settings.value("mode", "encrypt", str), initial=True)

    # -- layout --
    def _build(self):
        # header
        title = QLabel(APP_NAME)
        title.setObjectName("title")
        sub = QLabel("Encrypt files and folders before they go to the cloud.")
        sub.setObjectName("muted")
        head_l = QVBoxLayout()
        head_l.setSpacing(2)
        head_l.addWidget(title)
        head_l.addWidget(sub)

        self.btn_enc = QPushButton("Encrypt")
        self.btn_dec = QPushButton("Decrypt")
        self.btn_ver = QPushButton("Verify")
        seg = QButtonGroup(self)
        seg.setExclusive(True)
        for b, m in ((self.btn_enc, "encrypt"), (self.btn_dec, "decrypt"), (self.btn_ver, "verify")):
            b.setCheckable(True)
            b.setProperty("seg", True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            seg.addButton(b)
            b.clicked.connect(lambda _=False, m=m: self.set_mode(m))
        segbar = QFrame()
        segbar.setObjectName("segbar")
        seg_l = QHBoxLayout(segbar)
        seg_l.setContentsMargins(4, 4, 4, 4)
        seg_l.setSpacing(2)
        seg_l.addWidget(self.btn_enc)
        seg_l.addWidget(self.btn_dec)
        seg_l.addWidget(self.btn_ver)

        header = QHBoxLayout()
        header.addLayout(head_l)
        header.addStretch(1)
        header.addWidget(segbar)

        # queue
        self.drop = DropFrame()
        self.drop.dropped.connect(self.add_paths)
        self.stack = QStackedLayout(self.drop)
        self.stack.setContentsMargins(4, 4, 4, 4)

        ph = QWidget()
        ph_l = QVBoxLayout(ph)
        ph_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ph_icon = QLabel("🔒")
        self.ph_icon.setStyleSheet("font-size: 40px;")
        self.ph_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ph_title = QLabel()
        self.ph_title.setObjectName("bigdrop")
        self.ph_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ph_hint = QLabel()
        self.ph_hint.setObjectName("muted")
        self.ph_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ph_hint.setWordWrap(True)
        ph_l.addWidget(self.ph_icon)
        ph_l.addSpacing(6)
        ph_l.addWidget(self.ph_title)
        ph_l.addWidget(self.ph_hint)
        self.stack.addWidget(ph)

        self.list = QListWidget()
        self.list.setAcceptDrops(False)
        self.list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.stack.addWidget(self.list)

        self.count_lbl = QLabel("")
        self.count_lbl.setObjectName("muted")
        self.add_files_btn = QPushButton("Add files…")
        self.add_folder_btn = QPushButton("Add folder…")
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("ghost")
        self.add_files_btn.clicked.connect(self.pick_files)
        self.add_folder_btn.clicked.connect(self.pick_folder)
        self.clear_btn.clicked.connect(self.clear_jobs)
        foot = QHBoxLayout()
        foot.addWidget(self.count_lbl)
        foot.addStretch(1)
        foot.addWidget(self.clear_btn)
        foot.addWidget(self.add_files_btn)
        foot.addWidget(self.add_folder_btn)

        self.overall = QProgressBar()
        self.overall.setObjectName("overall")
        self.overall.setTextVisible(False)
        self.overall.setRange(0, 1000)
        self.status = ElidedLabel("")
        self.status.setObjectName("muted")
        self.open_btn = QPushButton("Show in folder")
        self.open_btn.setObjectName("ghost")
        self.open_btn.setVisible(False)
        self.open_btn.clicked.connect(self.open_output)
        self.log_btn = QPushButton("Details")
        self.log_btn.setObjectName("ghost")
        self.log_btn.setCheckable(True)
        status_row = QHBoxLayout()
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.open_btn)
        status_row.addWidget(self.log_btn)
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(130)
        self.log.setVisible(False)
        self.log_btn.toggled.connect(self.log.setVisible)

        left = QVBoxLayout()
        left.setSpacing(10)
        left.addWidget(self.drop, 1)
        left.addLayout(foot)
        left.addSpacing(4)
        left.addWidget(self.overall)
        left.addLayout(status_row)
        left.addWidget(self.log)

        # settings column
        self.panel = QWidget()
        pl = QVBoxLayout(self.panel)
        pl.setContentsMargins(0, 0, 12, 0)   # room for the scrollbar
        pl.setSpacing(8)

        def section(text):
            lbl = QLabel(text)
            lbl.setObjectName("section")
            return lbl

        def small(text):
            lbl = QLabel(text)
            lbl.setObjectName("small")
            return lbl

        pl.addWidget(section("Password"))
        self.pw1 = QLineEdit()
        self.pw1.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw1.setPlaceholderText("Password")
        self.pw1.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.pw2 = QLineEdit()
        self.pw2.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2.setPlaceholderText("Repeat password")
        self.show_pw = QCheckBox("Show password")
        self.strength = QProgressBar()
        self.strength.setTextVisible(False)
        self.strength.setRange(0, 100)
        self.strength_lbl = small("")
        self.strength_lbl.setWordWrap(True)
        self.weak_chk = QCheckBox("Use this weak password anyway")
        self.confirm_box = QWidget()
        cb = QVBoxLayout(self.confirm_box)
        cb.setContentsMargins(0, 0, 0, 0)
        cb.setSpacing(8)
        cb.addWidget(self.pw2)
        cb.addWidget(self.strength)
        cb.addWidget(self.strength_lbl)
        cb.addWidget(self.weak_chk)
        pl.addWidget(self.pw1)
        pl.addWidget(self.confirm_box)
        pl.addWidget(self.show_pw)

        # key file: a second secret next to the password
        self.kf_path = ""
        self.kf_box = QWidget()
        kb = QVBoxLayout(self.kf_box)
        kb.setContentsMargins(0, 4, 0, 0)
        kb.setSpacing(6)
        self.kf_chk = QCheckBox("Also require a key file")
        self.kf_chk.setToolTip("Two factors: to open the files you will need the password AND this file.")
        kb.addWidget(self.kf_chk)
        self.kf_title = small("Key file")
        kb.addWidget(self.kf_title)
        self.kf_row = QWidget()
        kr = QHBoxLayout(self.kf_row)
        kr.setContentsMargins(0, 0, 0, 0)
        self.kf_lbl = ElidedLabel("")
        self.kf_lbl.setObjectName("muted")
        self.kf_choose = QPushButton("Choose…")
        self.kf_create = QPushButton("Create…")
        self.kf_clear = QPushButton("✕")
        self.kf_clear.setToolTip("Don't use a key file")
        self.kf_clear.setFixedWidth(34)
        kr.addWidget(self.kf_lbl, 1)
        kr.addWidget(self.kf_choose)
        kr.addWidget(self.kf_create)
        kr.addWidget(self.kf_clear)
        kb.addWidget(self.kf_row)
        self.kf_info = small("")
        self.kf_info.setWordWrap(True)
        kb.addWidget(self.kf_info)
        pl.addWidget(self.kf_box)
        self.kf_chk.toggled.connect(self._keyfile_toggled)
        self.kf_choose.clicked.connect(self.pick_keyfile)
        self.kf_create.clicked.connect(self.create_keyfile)
        self.kf_clear.clicked.connect(lambda: self.set_keyfile(""))
        self.pw1.textChanged.connect(self.update_strength)
        self.pw1.returnPressed.connect(self.on_start)
        self.pw2.returnPressed.connect(self.on_start)
        self.show_pw.toggled.connect(self._toggle_echo)

        pl.addSpacing(6)
        hl = QFrame()
        hl.setObjectName("hline")
        pl.addWidget(hl)
        pl.addSpacing(6)

        # encrypt-only options
        self.enc_opts = QWidget()
        eo = QVBoxLayout(self.enc_opts)
        eo.setContentsMargins(0, 0, 0, 0)
        eo.setSpacing(6)
        eo.addWidget(section("Options"))
        eo.addWidget(small("Compression"))
        self.cmb_comp = _combo([("Automatic (recommended)", "auto"), ("Fast", "fast"),
                                ("Smallest (slow)", "lzma"), ("None", "none")], "auto")
        eo.addWidget(self.cmb_comp)
        eo.addWidget(small("Key strength"))
        self.cmb_kdf = _combo([("Strong (128 MB of memory)", "strong"),
                               ("Light (for older computers)", "light"),
                               ("Tuned to this computer", "auto")], "strong")
        eo.addWidget(self.cmb_kdf)
        eo.addWidget(small("After encrypting"))
        trash_name = "Recycle Bin" if sys.platform.startswith("win") else "Trash"
        after_items = [("Keep the originals (safest)", "keep")]
        if core.TRASH_AVAILABLE:
            after_items.append((f"Move the originals to the {trash_name}", "trash"))
        after_items += [("Delete the originals permanently", "delete"),
                        ("Overwrite, then delete (best effort)", "wipe")]
        self.cmb_after = _combo(after_items, "keep")
        self.cmb_after.setToolTip(
            "Originals are only touched after the encrypted file was read back, decrypted in full and "
            "matched the original byte for byte. Overwriting is not a guaranteed erase on SSDs.")
        eo.addWidget(self.cmb_after)
        self.chk_verify = QCheckBox("Check the encrypted file before finishing")
        self.chk_verify.setChecked(True)
        eo.addWidget(self.chk_verify)
        eo.addSpacing(4)
        eo.addWidget(small("File extension"))
        self.ext_edit = QLineEdit()
        self.ext_edit.setPlaceholderText(core.DEFAULT_EXTENSION)
        self.ext_edit.setMaxLength(24)
        self.ext_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.ext_edit.setToolTip("Added to the name of every encrypted file or folder. Leave empty to use .enc")
        eo.addWidget(self.ext_edit)
        self.ext_preview = small("")
        self.ext_preview.setWordWrap(True)
        eo.addWidget(self.ext_preview)
        self.ext_edit.textChanged.connect(self._refresh_ext_ui)
        eo.addSpacing(6)
        hl2 = QFrame()
        hl2.setObjectName("hline")
        eo.addWidget(hl2)
        eo.addSpacing(6)
        self.cmb_after.currentIndexChanged.connect(self._after_changed)
        pl.addWidget(self.enc_opts)

        self.save_box = QWidget()
        sb = QVBoxLayout(self.save_box)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.setSpacing(8)
        sb.addWidget(section("Save to"))
        self.cmb_out = _combo([("Next to each original", "same"), ("A folder I choose", "custom")], "same")
        sb.addWidget(self.cmb_out)
        self.out_row = QWidget()
        orow = QHBoxLayout(self.out_row)
        orow.setContentsMargins(0, 0, 0, 0)
        self.out_lbl = ElidedLabel("")
        self.out_lbl.setObjectName("muted")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self.pick_out_folder)
        orow.addWidget(self.out_lbl, 1)
        orow.addWidget(browse)
        sb.addWidget(self.out_row)
        sb.addWidget(small("If a file already exists"))
        self.cmb_over = _combo([("Keep both (add a number)", "rename"), ("Replace it", "overwrite"),
                                ("Skip it", "skip")], "rename")
        sb.addWidget(self.cmb_over)
        self.cmb_out.currentIndexChanged.connect(self._out_changed)
        pl.addWidget(self.save_box)

        self.verify_note = QLabel(
            "Nothing is written to disk. Each file is read completely: the password, every block "
            "and the total size are checked, so you know it will decrypt before you rely on it.")
        self.verify_note.setObjectName("muted")
        self.verify_note.setWordWrap(True)
        pl.addWidget(self.verify_note)
        pl.addStretch(1)

        self.start_btn = QPushButton("Encrypt")
        self.start_btn.setObjectName("primary")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.clicked.connect(self.on_start)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("danger")
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.clicked.connect(self.on_cancel)
        self.cancel_btn.setVisible(False)

        right = QVBoxLayout()
        right.setSpacing(10)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self.panel)
        right.addWidget(scroll, 1)
        right.addWidget(self.start_btn)
        right.addWidget(self.cancel_btn)
        right_w = QWidget()
        right_w.setFixedWidth(344)
        right_w.setLayout(right)
        right.setContentsMargins(0, 0, 0, 0)

        vline = QFrame()
        vline.setObjectName("vline")
        body = QHBoxLayout()
        body.setSpacing(20)
        body.addLayout(left, 1)
        body.addWidget(vline)
        body.addWidget(right_w)

        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 22)
        root.setSpacing(18)
        root.addLayout(header)
        root.addLayout(body, 1)

    # -- settings --
    def _load_settings(self):
        s = self.settings
        for cb, key in ((self.cmb_comp, "comp"), (self.cmb_kdf, "kdf"), (self.cmb_over, "over")):
            idx = cb.findData(s.value(key, cb.currentData(), str))
            if idx >= 0:
                cb.setCurrentIndex(idx)
        self.chk_verify.setChecked(s.value("verify", True, bool))
        self.log_btn.setChecked(s.value("log", False, bool))
        self.ext_edit.setText(s.value("ext", "", str))
        self.kf_path = s.value("keyfile", "", str)
        self.kf_chk.setChecked(s.value("keyfile_on", False, bool))

    def _save_settings(self):
        s = self.settings
        s.setValue("mode", self.mode)
        for cb, key in ((self.cmb_comp, "comp"), (self.cmb_kdf, "kdf"), (self.cmb_over, "over")):
            s.setValue(key, cb.currentData())
        s.setValue("verify", self.chk_verify.isChecked())
        s.setValue("log", self.log_btn.isChecked())
        s.setValue("keyfile", self.kf_path)           # only the location, never the contents
        s.setValue("keyfile_on", self.kf_chk.isChecked())
        s.setValue("ext_history", ",".join(self.ext_history))
        ext, err = self._ext_state()
        if not err:
            s.setValue("ext", "" if ext == core.DEFAULT_EXTENSION else ext)
        self._stash_destination()
        for m in ("encrypt", "decrypt"):
            s.setValue(f"out_{m}", self.out_choice[m])
            s.setValue(f"out_folder_{m}", self.out_folders[m])
        s.remove("out")
        s.remove("out_folder")

    # -- mode / theme --
    def _stash_destination(self):
        """Remember what the 'Save to' controls say for the mode being left."""
        if self.mode in self.out_choice:
            self.out_choice[self.mode] = self.cmb_out.currentData()

    def _apply_destination(self, mode: str) -> str:
        """Show the saved 'Save to' choice of this mode. Returns a note if it had to fall back."""
        if mode not in self.out_choice:
            return ""
        choice, folder, note = self.out_choice[mode], self.out_folders[mode], ""
        if choice == "custom" and not os.path.isdir(folder):
            if folder:
                note = (f"The folder saved for {'encrypting' if mode == 'encrypt' else 'decrypting'} "
                        "is not available, so files go next to the originals.")
            choice = "same"
        self.cmb_out.blockSignals(True)
        self.cmb_out.setCurrentIndex(self.cmb_out.findData(choice))
        self.cmb_out.blockSignals(False)
        self.out_row.setVisible(choice == "custom")
        self.out_lbl.setText(folder or "No folder chosen")
        return note

    def set_mode(self, mode: str, initial: bool = False):
        if mode not in ("encrypt", "decrypt", "verify"):
            mode = "encrypt"
        if self.worker is not None:
            return
        changed = mode != self.mode
        same_kind = {self.mode, mode} <= {"decrypt", "verify"}   # both work on .enc files
        if changed and self.jobs:
            if same_kind:
                for j in self.jobs:
                    j.row.reset()
                self.overall.setValue(0)
                self.overall.setStyleSheet("")
            else:
                self.clear_jobs()
                self.flash("List cleared because you switched mode.", "muted")
        if not initial:
            self._stash_destination()
        self.mode = mode
        THEME["accent"] = ACCENTS[mode]
        QApplication.instance().setStyleSheet(build_qss(THEME["accent"]))
        self.btn_enc.setChecked(mode == "encrypt")
        self.btn_dec.setChecked(mode == "decrypt")
        self.btn_ver.setChecked(mode == "verify")
        enc, ver = mode == "encrypt", mode == "verify"
        self.confirm_box.setVisible(enc)
        self.enc_opts.setVisible(enc)
        self.save_box.setVisible(not ver)
        self.verify_note.setVisible(ver)
        note = self._apply_destination(mode)
        self.pw1.setPlaceholderText("Password" if enc else "Password used to encrypt")
        icon, title, hint = {
            "encrypt": ("🔒", "Drop files or folders to encrypt", self._encrypt_hint()),
            "decrypt": ("🔓", "Drop encrypted files to decrypt",
                        "You can also drop a folder: every encrypted file inside it is added."),
            "verify": ("🔍", "Drop encrypted files to verify",
                       "Checks that a file is complete and the password is right, "
                       "without writing anything to disk."),
        }[mode]
        self.ph_icon.setText(icon)
        self.ph_title.setText(title)
        self.ph_hint.setText(hint)
        self.pw1.clear()
        self.pw2.clear()
        self.update_strength()
        self.refresh_queue()      # also refreshes the key file area
        if note:
            self.flash(note, "muted")
        elif not initial:
            self.flash("", "muted")

    # -- file extension --
    def _ext_state(self):
        """(extension, error): the cleaned extension typed in the field, or an error message."""
        try:
            return core.clean_extension(self.ext_edit.text()), ""
        except ValueError as e:
            return None, str(e)

    def _known_exts(self) -> list:
        """Extensions this app has produced (or is about to): used to recognise and strip them."""
        out = [core.DEFAULT_EXTENSION]
        ext, err = self._ext_state()
        for e in self.ext_history + ([ext] if not err else []):
            if e not in out:
                out.append(e)
        return out

    def _remember_ext(self, ext: str):
        self.ext_history = [e for e in self.ext_history if e != ext]
        if ext != core.DEFAULT_EXTENSION:
            self.ext_history.insert(0, ext)
        del self.ext_history[12:]
        self.settings.setValue("ext_history", ",".join(self.ext_history))
        self.settings.setValue("ext", "" if ext == core.DEFAULT_EXTENSION else ext)
        self.settings.sync()

    def _encrypt_hint(self) -> str:
        ext, err = self._ext_state()
        return f"Each file or folder becomes one .{ext or core.DEFAULT_EXTENSION} file you can upload to the cloud."

    def _refresh_ext_ui(self):
        ext, err = self._ext_state()
        if self._ext_flash and self.status._full == self._ext_flash:
            self.flash("", "muted")   # the error shown at the bottom was about the old text
            self._ext_flash = ""
        if err:
            self.ext_preview.setStyleSheet(f"color: {C['err']};")
            self.ext_preview.setText(err)
        else:
            sample = "example.pdf"
            if self.jobs and self.mode == "encrypt":
                sample = os.path.basename(self.jobs[0].path.rstrip("\\/")) or sample
            if len(sample) > 30:
                sample = sample[:27] + "…"
            self.ext_preview.setStyleSheet("")
            self.ext_preview.setText(f"Result: {sample}.{ext}")
        if self.mode == "encrypt":
            self.ph_hint.setText(self._encrypt_hint())

    # -- queue --
    def pick_files(self):
        if self.mode in ("decrypt", "verify"):
            masks = " ".join(f"*.{e}" for e in self._known_exts())
            paths, _ = QFileDialog.getOpenFileNames(self, "Choose encrypted files", "",
                                                    f"Encrypted files ({masks});;All files (*)")
        else:
            paths, _ = QFileDialog.getOpenFileNames(self, "Choose files to encrypt")
        if paths:
            self.add_paths(paths)

    def pick_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose a folder")
        if path:
            self.add_paths([path])

    def add_paths(self, paths: list):
        if self.worker is not None:
            return
        paths = [os.path.normpath(p) for p in paths]
        if (self.mode == "encrypt" and not self.jobs and paths
                and all(core.is_encv_file(p) for p in paths)):
            self.set_mode("decrypt")
            self.flash("Those files are already encrypted, so I switched to Decrypt.", "muted")
        existing = {j.path for j in self.jobs}
        skipped = 0
        for p in paths:
            if p in existing:
                continue
            if self.mode == "encrypt":
                if os.path.isdir(p):
                    self._add_job(p, "folder")
                elif core.is_encv_file(p):
                    skipped += 1
                    self.append_log(f"Not added (already encrypted): {p}")
                elif os.path.isfile(p):
                    self._add_job(p, "file")
            else:
                found = []
                if os.path.isdir(p):
                    for root, _dirs, files in os.walk(p):
                        found += [os.path.join(root, f) for f in sorted(files)
                                  if core.is_encv_file(os.path.join(root, f))]
                elif core.is_encv_file(p):
                    found = [p]
                if not found:
                    skipped += 1
                    self.append_log(f"Not added (not an encrypted file from this app): {p}")
                for f in found:
                    if f not in existing:
                        self._add_job(f, "enc")
                        existing.add(f)
        self.refresh_queue()
        if skipped:
            self.flash(f"{skipped} item{'s' if skipped != 1 else ''} not added (see Details).", "muted")

    def _add_job(self, path: str, kind: str):
        row = JobRow(path, kind)
        item = QListWidgetItem()
        item.setSizeHint(QSize(0, 70))
        self.list.addItem(item)
        self.list.setItemWidget(item, row)
        job = Job(path, kind, item, row)
        row.removed.connect(lambda _r, j=job: self.remove_job(j))
        self.jobs.append(job)

    def remove_job(self, job: Job):
        if self.worker is not None:
            return
        self.list.takeItem(self.list.row(job.item))
        job.row.deleteLater()
        self.jobs.remove(job)
        self.refresh_queue()

    def clear_jobs(self):
        if self.worker is not None:
            return
        self.list.clear()
        self.jobs.clear()
        self.overall.setValue(0)
        self.open_btn.setVisible(False)
        self.refresh_queue()

    def refresh_queue(self):
        n = len(self.jobs)
        self.stack.setCurrentIndex(1 if n else 0)
        self.count_lbl.setText(f"{n} item{'s' if n != 1 else ''}" if n else "")
        self.clear_btn.setEnabled(n > 0 and self.worker is None)
        verb = {"encrypt": "Encrypt", "decrypt": "Decrypt", "verify": "Verify"}[self.mode]
        self.start_btn.setText(f"{verb} {n} item{'s' if n != 1 else ''}" if n else verb)
        self.start_btn.setEnabled(n > 0 and self.worker is None)
        self._refresh_ext_ui()
        if hasattr(self, "kf_box"):
            self._refresh_keyfile_ui()

    # -- key file --
    def _jobs_needing_keyfile(self) -> int:
        if self.mode == "encrypt":
            return 0
        return sum(1 for j in self.jobs if core.file_needs_keyfile(j.path))

    def set_keyfile(self, path: str):
        self.kf_path = path
        self._refresh_keyfile_ui()

    def _keyfile_toggled(self, on: bool):
        self._refresh_keyfile_ui()

    def pick_keyfile(self):
        start = os.path.dirname(self.kf_path) if self.kf_path else os.path.expanduser("~")
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose the key file", start,
            f"Key files (*.{core.KEYFILE_EXTENSION});;All files (*)")
        if path:
            self.set_keyfile(os.path.normpath(path))
            if self.mode == "encrypt":
                self.kf_chk.setChecked(True)

    def create_keyfile(self):
        dlg = KeyfileDialog(self, os.path.dirname(self.kf_path) if self.kf_path else "")
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.path:
            self.set_keyfile(dlg.path)
            self.kf_chk.setChecked(True)

    def _keyfile_id_text(self):
        """(text, ok) describing the chosen key file."""
        if not self.kf_path:
            return "", True
        try:
            digest = core.load_keyfile(self.kf_path)
        except core.FormatError as e:
            return f"⚠ {e}", False
        return f"Key ID: {core.keyfile_id(digest)}  (the same ID must show when you decrypt)", True

    def _refresh_keyfile_ui(self):
        enc = self.mode == "encrypt"
        self.kf_chk.setVisible(enc)
        self.kf_create.setVisible(enc)
        self.kf_clear.setVisible(not enc)
        show_row = (self.kf_chk.isChecked() if enc else True)
        self.kf_title.setVisible(not enc)
        self.kf_title.setText("Key file (only if the files were protected with one)")
        self.kf_row.setVisible(show_row)
        self.kf_lbl.setText(self.kf_path or "No key file chosen")
        text, ok = self._keyfile_id_text()
        color = C["muted"]
        if enc:
            if show_row and ok:
                text = (text + "\n" if text else "") + ("Keep it apart from your encrypted files, and make a backup: "
                                                        "without it AND the password nothing can be opened.")
            elif not show_row:
                text = ""
        else:
            need = self._jobs_needing_keyfile()
            if not ok:
                pass
            elif need and not self.kf_path:
                text, color = f"⚠ {need} of these files {'needs' if need == 1 else 'need'} a key file. Choose it first.", C["err"]
            elif need:
                pass
            elif self.jobs and self.kf_path:
                text = "None of these files needs a key file; it will be ignored."
            elif not self.kf_path:
                text = ""
        if not ok:
            color = C["err"]
        self.kf_info.setStyleSheet(f"color: {color};")
        self.kf_info.setText(text)
        self.kf_info.setVisible(bool(text))

    def _keyfile_for_run(self):
        """(path or None, error). Validates before anything starts."""
        if self.mode == "encrypt":
            if not self.kf_chk.isChecked():
                return None, ""
            if not self.kf_path:
                return None, "Choose or create a key file, or untick “Also require a key file”."
        else:
            need = self._jobs_needing_keyfile()
            if not self.kf_path:
                if need:
                    return None, f"{need} of these files {'needs' if need == 1 else 'need'} a key file. Choose it first."
                return None, ""
        try:
            core.load_keyfile(self.kf_path)
        except core.FormatError as e:
            return None, str(e)
        return self.kf_path, ""

    # -- settings widgets --
    def _toggle_echo(self, on: bool):
        mode = QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
        self.pw1.setEchoMode(mode)
        self.pw2.setEchoMode(mode)

    def update_strength(self):
        pw = self.pw1.text()
        if self.mode != "encrypt":
            return
        color, text = C["muted"], "Use a long passphrase, for example four random words."
        value, weak = 0, False
        if pw:
            ent, ok = core.password_strength(pw)
            value = max(min(int(ent / 80 * 100), 100), 4)
            if not ok:
                weak, color = True, C["err"]
                text = f"Too weak (about {ent:.0f} bits). Try a passphrase of 4+ random words."
            elif ent < 70:
                color, text = THEME["accent"], "Good."
            else:
                color, text = C["ok"], "Strong."
        self.strength.setValue(value)
        self.strength.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; border-radius: 2px; }}")
        self.strength_lbl.setText(text)
        self.weak_chk.setVisible(weak)
        if not weak:
            self.weak_chk.setChecked(False)

    def _after_changed(self):
        destructive = self.cmb_after.currentData() != "keep"
        if destructive:
            self.chk_verify.setChecked(True)
        self.chk_verify.setEnabled(not destructive)

    def _confirm_remove_originals(self, after: str) -> bool:
        trash_name = "Recycle Bin" if sys.platform.startswith("win") else "Trash"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        if after == "trash":
            box.setWindowTitle(f"Move the originals to the {trash_name}?")
            box.setText(f"Each original goes to the {trash_name} once its encrypted copy was written and checked.")
            box.setInformativeText(f"You can still restore it from the {trash_name} until you empty it. "
                                   "Without the password the encrypted copy cannot be opened.")
            go = box.addButton("Encrypt and move", QMessageBox.ButtonRole.DestructiveRole)
            confirm = None
        else:
            box.setWindowTitle("Remove the originals?")
            box.setText("The originals will be removed permanently once their encrypted copies were written and checked.")
            extra = ("\n\nOverwriting is best-effort: on SSDs, USB sticks, synced folders and snapshots, "
                     "old copies of the data can remain. For real protection use full-disk encryption."
                     if after == "wipe" else "")
            box.setInformativeText(
                "The check decrypts the new file completely and compares it with the original, but it cannot "
                "know whether the file will survive an upload. Safest: keep the originals, upload, run "
                "Verify on the uploaded copy, then delete them yourself." + extra)
            go = box.addButton("Encrypt and remove", QMessageBox.ButtonRole.DestructiveRole)
            confirm = QCheckBox("I remember the password and have a second copy or a backup")
            box.setCheckBox(confirm)
            go.setEnabled(False)
            confirm.toggled.connect(go.setEnabled)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel)
        box.exec()
        return box.clickedButton() is go

    def _out_changed(self):
        mode = self.mode
        if mode not in self.out_folders:
            return
        custom = self.cmb_out.currentData() == "custom"
        self.out_row.setVisible(custom)
        if custom:
            if not self.out_folders[mode]:
                self.pick_out_folder()
            self.out_lbl.setText(self.out_folders[mode] or "No folder chosen")
        self.out_choice[mode] = self.cmb_out.currentData()

    def pick_out_folder(self):
        mode = self.mode
        if mode not in self.out_folders:
            return
        path = QFileDialog.getExistingDirectory(self, "Choose where to save", self.out_folders[mode])
        if path:
            self.out_folders[mode] = os.path.normpath(path)
        elif not self.out_folders[mode]:
            self.cmb_out.setCurrentIndex(self.cmb_out.findData("same"))
        self.out_lbl.setText(self.out_folders[mode] or "No folder chosen")

    # -- status helpers --
    def flash(self, text: str, kind: str = "muted"):
        color = {"muted": C["muted"], "ok": C["ok"], "err": C["err"]}[kind]
        self.status.setStyleSheet(f"color: {color};")
        self.status.setText(text)

    def append_log(self, msg: str):
        self.log.appendPlainText(msg)

    def open_output(self):
        if self.last_output_dir and os.path.isdir(self.last_output_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.last_output_dir))

    # -- run --
    def on_start(self):
        if self.worker is not None or not self.jobs:
            return
        enc = self.mode == "encrypt"
        pw = self.pw1.text()
        if not pw:
            self.flash("Enter a password first.", "err")
            self.pw1.setFocus()
            return
        if enc:
            if pw != self.pw2.text():
                self.flash("The two passwords don't match.", "err")
                self.pw2.setFocus()
                return
            _ent, ok = core.password_strength(pw)
            if not ok and not self.weak_chk.isChecked():
                self.flash("That password is too weak. Pick a longer one, or tick “Use this weak password anyway”.", "err")
                self.pw1.setFocus()
                return
            ext, ext_err = self._ext_state()
            if ext_err:
                self._ext_flash = ext_err
                self.flash(ext_err, "err")
                self.ext_edit.setFocus()
                return
            after = self.cmb_after.currentData()
            if after != "keep" and not self._confirm_remove_originals(after):
                return
        keyfile, kf_err = self._keyfile_for_run()
        if kf_err:
            self.flash(kf_err, "err")
            return
        out_dir = None
        if self.mode != "verify" and self.cmb_out.currentData() == "custom":
            folder = self.out_folders[self.mode]
            if not folder or not os.path.isdir(folder):
                self.flash("Choose a folder to save to.", "err")
                return
            out_dir = folder

        opts = core.EncryptOptions(
            kdf_profile=self.cmb_kdf.currentData(), compression=self.cmb_comp.currentData(),
            verify=self.chk_verify.isChecked(), after=self.cmb_after.currentData(),
            overwrite=self.cmb_over.currentData(), keyfile=keyfile if enc else None,
            extension=self._ext_state()[0] or core.DEFAULT_EXTENSION)
        if enc:
            self._remember_ext(opts.extension)
        self.row_frac = [0.0] * len(self.jobs)
        self.overall.setStyleSheet("")
        for j in self.jobs:
            j.row.set_state("ready", "Waiting", 0.0)
        self.overall.setValue(0)
        self.open_btn.setVisible(False)
        self.last_output_dir = ""
        self.log.clear()
        self.worker = Worker(self.mode, [j.path for j in self.jobs], pw, out_dir, opts,
                             self.cmb_over.currentData(), self._known_exts(), keyfile=keyfile)
        self.worker.row_update.connect(self.on_row_update)
        self.worker.log.connect(self.append_log)
        self.worker.output_dir.connect(self._remember_output)
        self.worker.summary.connect(self.on_summary)
        self.set_busy(True)
        self.worker.start()

    def on_cancel(self):
        if self.worker:
            self.worker.cancel.set()
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.setText("Cancelling…")

    def _remember_output(self, d: str):
        if not self.last_output_dir:
            self.last_output_dir = d

    def set_busy(self, busy: bool):
        self.panel.setEnabled(not busy)
        self.btn_enc.setEnabled(not busy)
        self.btn_dec.setEnabled(not busy)
        self.btn_ver.setEnabled(not busy)
        self.add_files_btn.setEnabled(not busy)
        self.add_folder_btn.setEnabled(not busy)
        self.drop.setAcceptDrops(not busy)
        self.start_btn.setVisible(not busy)
        self.cancel_btn.setVisible(busy)
        self.cancel_btn.setEnabled(True)
        self.cancel_btn.setText("Cancel")
        for j in self.jobs:
            j.row.set_busy(busy)
        self.refresh_queue()

    def on_row_update(self, idx, state, frac, text, detail):
        if idx >= len(self.jobs):
            return
        self.jobs[idx].row.set_state(state, text, frac, detail)
        self.row_frac[idx] = 1.0 if state in ("ok", "error", "skipped", "cancelled") else frac
        n = len(self.row_frac)
        self.overall.setValue(int(sum(self.row_frac) / n * 1000))
        if state == "running":
            name = os.path.basename(self.jobs[idx].path.rstrip("\\/"))
            verb = {"encrypt": "Encrypting", "decrypt": "Decrypting", "verify": "Verifying"}[self.mode]
            self.flash(f"{verb} {name}  ({idx + 1} of {n})")
            if self.jobs[idx].row.parent() is not None:
                self.list.scrollToItem(self.jobs[idx].item)

    def on_summary(self, ok, failed, skipped, cancelled):
        worker, self.worker = self.worker, None
        if worker:
            worker.wait()
            worker.deleteLater()
        self.set_busy(False)
        parts = [f"{ok} verified" if self.mode == "verify" else f"{ok} done"]
        if failed:
            parts.append(f"{failed} failed")
        if skipped:
            parts.append(f"{skipped} skipped")
        if cancelled:
            parts.append(f"{cancelled} cancelled")
        self.flash("Finished: " + ", ".join(parts) + ".", "err" if failed else "ok")
        if failed:
            self.overall.setStyleSheet(f"QProgressBar#overall::chunk {{ background: {C['err']}; }}")
        if ok and failed == 0 and cancelled == 0:
            self.pw1.clear()
            self.pw2.clear()
        self.open_btn.setVisible(bool(self.last_output_dir))
        QApplication.alert(self)

    def closeEvent(self, e):  # noqa: N802
        if self.worker is not None:
            ans = QMessageBox.question(self, "Stop and quit?",
                                       "A job is still running. Stop it and quit?")
            if ans != QMessageBox.StandardButton.Yes:
                e.ignore()
                return
            self.worker.cancel.set()
            self.worker.wait(8000)
        self._save_settings()
        e.accept()


def _selftest() -> int:
    """Tiny encrypt/decrypt round trip; exit code 0 = engine works (used to check the built exe)."""
    import shutil
    import tempfile
    d = tempfile.mkdtemp()
    try:
        data = os.urandom(300_000) + b"A" * 300_000
        src = os.path.join(d, "t.bin")
        with open(src, "wb") as f:
            f.write(data)
        pw = "selftest passphrase 123!"
        r = core.encrypt_path(src, d, pw, core.EncryptOptions(kdf_profile="light"))
        if core.verify_path(r.output, pw).out_size != len(data):
            return 1
        r2 = core.decrypt_path(r.output, os.path.join(d, "out"), pw)
        with open(r2.output, "rb") as f:
            if f.read() != data:
                return 1
        try:   # a header asking for absurd key settings must be refused before any work
            core.derive_key(pw, b"s" * 16, 999, 4194304, 255)
            return 1
        except core.FormatError:
            pass
        folder = os.path.join(d, "Folder")
        os.makedirs(os.path.join(folder, "sub"))
        with open(os.path.join(folder, "sub", "x.txt"), "w") as f:
            f.write("hello")
        r3 = core.encrypt_path(folder, d, pw, core.EncryptOptions(kdf_profile="light"))
        r4 = core.decrypt_path(r3.output, os.path.join(d, "out2"), pw)
        with open(os.path.join(r4.output, "sub", "x.txt")) as f:
            if f.read() != "hello":
                return 1
        kf = os.path.join(d, "t.encvkey")        # second factor: key file + password
        core.create_keyfile(kf, b"selftest")
        r5 = core.encrypt_path(src, os.path.join(d, "k"), pw, core.EncryptOptions(kdf_profile="light", keyfile=kf))
        try:
            core.verify_path(r5.output, pw)
            return 1                             # must not open without the key file
        except core.FormatError:
            pass
        r6 = core.decrypt_path(r5.output, os.path.join(d, "out3"), pw, keyfile=kf)
        with open(r6.output, "rb") as f:
            return 0 if f.read() == data else 1
    except Exception:  # noqa: BLE001
        return 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    pal = QPalette()
    for role, col in ((QPalette.ColorRole.Window, C["bg"]), (QPalette.ColorRole.WindowText, C["text"]),
                      (QPalette.ColorRole.Base, C["field"]), (QPalette.ColorRole.AlternateBase, C["panel"]),
                      (QPalette.ColorRole.Text, C["text"]), (QPalette.ColorRole.Button, C["field"]),
                      (QPalette.ColorRole.ButtonText, C["text"]), (QPalette.ColorRole.ToolTipBase, C["panel"]),
                      (QPalette.ColorRole.ToolTipText, C["text"]), (QPalette.ColorRole.Highlight, ACCENTS["encrypt"]),
                      (QPalette.ColorRole.HighlightedText, C["on_accent"]), (QPalette.ColorRole.PlaceholderText, "#75849b")):
        pal.setColor(role, QColor(col))
    app.setPalette(pal)
    win = MainWindow()
    win.show()
    # Files passed on the command line (e.g. "Open with") are added right away.
    args = [a for a in sys.argv[1:] if os.path.exists(a)]
    if args:
        win.add_paths(args)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
