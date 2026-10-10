"""
Drives the real window without a screen (Qt "offscreen"): the buttons and options must reach the engine.
Skipped when PySide6 is not installed.   Run:  python -m pytest tests
"""

import os
import sys

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings          # noqa: E402
from PySide6.QtWidgets import QApplication     # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cryptid_core as core    # noqa: E402
import cryptid_gui as gui      # noqa: E402

PW = "correct horse battery staple 42!"


@pytest.fixture
def win(tmp_path, monkeypatch):
    # Settings go to a throw-away file, never to the real ones of whoever runs the tests.
    ini = str(tmp_path / "settings.ini")
    monkeypatch.setattr(gui, "QSettings", lambda *a: QSettings(ini, QSettings.Format.IniFormat))
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(QApplication, "alert", lambda *a, **k: None)
    w = gui.MainWindow()
    w.cmb_kdf.setCurrentIndex(w.cmb_kdf.findData("light"))      # fast key derivation for the tests
    w.show()
    yield w
    w.worker = None
    w.close()
    app.processEvents()


def run(w, timeout_s: float = 60.0):
    """Press the start button and wait for the job to finish."""
    w.on_start()
    assert w.worker is not None, w.status._full
    worker = w.worker
    assert worker.wait(int(timeout_s * 1000))
    for _ in range(50):
        QApplication.processEvents()
        if w.worker is None:
            break
    assert w.worker is None
    return w.status._full


def write(path, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return str(path)


def set_out(w, folder):
    os.makedirs(folder, exist_ok=True)
    w.out_folders[w.mode] = str(folder)
    w.cmb_out.setCurrentIndex(w.cmb_out.findData("custom"))


def test_encrypt_hidden_name_verify_decrypt(win, tmp_path):
    data = os.urandom(200_000)
    src = write(tmp_path / "in" / "Payroll 2026.xlsx", data)
    win.set_mode("encrypt")
    win.add_paths([src])
    set_out(win, tmp_path / "enc")
    win.chk_hide.setChecked(True)
    assert "random name" in win.ext_preview.text()
    win.pw1.setText(PW)
    win.pw2.setText(PW)
    assert "1 done" in run(win)
    (name,) = os.listdir(tmp_path / "enc")
    assert "Payroll" not in name and name.endswith(".enc")
    assert "name hidden" in win.jobs[0].row.info._full
    assert win.pw1.text() == ""                                  # cleared after a clean run

    win.set_mode("verify")
    win.add_paths([str(tmp_path / "enc" / name)])
    win.pw1.setText(PW)
    assert "1 verified" in run(win)
    assert "contains Payroll 2026.xlsx" in win.jobs[0].row.info._full

    win.set_mode("decrypt")                                      # verify -> decrypt keeps the list
    assert len(win.jobs) == 1 and win.chk_salvage.isVisible() and not win.chk_salvage.isChecked()
    set_out(win, tmp_path / "dec")
    win.pw1.setText(PW)
    assert "1 done" in run(win)
    with open(tmp_path / "dec" / "Payroll 2026.xlsx", "rb") as f:
        assert f.read() == data


def test_generated_password_must_be_confirmed_as_saved(win, tmp_path, monkeypatch):
    src = write(tmp_path / "in" / "a.txt", b"hello " * 1000)
    win.set_mode("encrypt")
    win.add_paths([src])
    set_out(win, tmp_path / "enc")
    assert not win.copy_pw_btn.isVisible()
    win.generate_password()
    pw = win.pw1.text()
    assert pw == win.pw2.text() and len(pw) == 29 and core.password_feedback(pw)[1]
    assert win.show_pw.isChecked() and win.copy_pw_btn.isVisible() and not win.weak_chk.isVisible()

    win.copy_generated_password()
    assert QApplication.clipboard().text() == pw
    win._clear_clipboard()
    assert QApplication.clipboard().text() == ""

    asked = []
    monkeypatch.setattr(win, "_confirm_password_saved", lambda: asked.append(1) or False)
    win.on_start()
    assert asked == [1] and win.worker is None and not os.listdir(tmp_path / "enc")   # "Go back": nothing happens

    monkeypatch.setattr(win, "_confirm_password_saved", lambda: True)
    assert "1 done" in run(win)
    assert win.pw1.text() == "" and not win.show_pw.isChecked()     # gone from the screen again
    (name,) = os.listdir(tmp_path / "enc")
    assert core.verify_path(str(tmp_path / "enc" / name), pw).out_size == 6000

    win.generate_password()                                      # typing over it hides Copy...
    pw2 = win.pw1.text()
    win.pw1.setText(PW)
    assert not win.copy_pw_btn.isVisible()
    win.pw1.setText(pw2)                                         # ...but putting it back is still "the generated one"
    win.pw2.setText(pw2)
    asked.clear()
    monkeypatch.setattr(win, "_confirm_password_saved", lambda: asked.append(1) or False)
    win.on_start()
    assert asked == [1] and win.worker is None and win.copy_pw_btn.isVisible()

    win.copy_generated_password()                                # an old timer must not clear a newer copy
    first = win._clip_token
    win.copy_generated_password()
    win._clear_clipboard(first)
    assert QApplication.clipboard().text() == pw2
    win._clear_clipboard(win._clip_token)
    assert QApplication.clipboard().text() == ""


def test_weak_password_is_explained_and_blocked(win, tmp_path):
    src = write(tmp_path / "in" / "a.txt", b"x")
    win.set_mode("encrypt")
    win.add_paths([src])
    for pw, word in (("qwertyuiopasdfgh", "predictable"), ("short", "short")):
        win.pw1.setText(pw)
        win.pw2.setText(pw)
        assert word in win.strength_lbl.text() and win.weak_chk.isVisible()
        win.on_start()
        assert win.worker is None and "too weak" in win.status._full


def test_damaged_file_all_or_nothing_unless_salvage(win, tmp_path):
    data = os.urandom(1_500_000)
    src = write(tmp_path / "in" / "movie.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, core.EncryptOptions(kdf_profile="light", compression="none"))
    with open(r.output, "rb") as f:
        blob = bytearray(f.read())
    blob[len(blob) * 2 // 3] ^= 0xFF
    bad = write(tmp_path / "enc" / "damaged.enc", bytes(blob))

    win.set_mode("decrypt")
    win.add_paths([bad])
    set_out(win, tmp_path / "dec")
    win.pw1.setText(PW)
    assert "1 failed" in run(win)
    assert os.listdir(tmp_path / "dec") == []

    win.chk_salvage.setChecked(True)
    win.pw1.setText(PW)
    summary = run(win)
    assert "1 only partly recovered" in summary and "0 done" in summary
    assert win.jobs[0].row.status.text() == "Incomplete"
    (name,) = os.listdir(tmp_path / "dec")
    assert name == "damaged.partial"
    with open(tmp_path / "dec" / name, "rb") as f:
        part = f.read()
    assert 0 < len(part) < len(data) and data.startswith(part)
    assert win.pw1.text() == PW                                  # not a clean run: the password stays for a retry


def test_settings_are_remembered_and_tests_leave_the_real_ones_alone(win, tmp_path):
    assert win.settings.fileName() == str(tmp_path / "settings.ini")
    assert not win.chk_hide.isChecked()                          # off unless asked for
    win.chk_hide.setChecked(True)
    win._save_settings()
    win.settings.sync()
    again = gui.MainWindow()
    assert again.chk_hide.isChecked() and again.cmb_kdf.currentData() == "light"
    assert not again.chk_salvage.isChecked()                     # the rescue option is never remembered


def test_too_deep_folder_is_stopped_with_a_reason(win, tmp_path):
    if os.name == "nt":
        pytest.skip("needs paths longer than Windows allows by default")
    p = tmp_path / "Deep"
    for _ in range(core.Limits().max_depth + 2):
        p = p / "d"
    write(p / "f.txt", b"x")
    win.set_mode("encrypt")
    win.add_paths([str(tmp_path / "Deep")])
    set_out(win, tmp_path / "enc")
    win.pw1.setText(PW)
    win.pw2.setText(PW)
    assert "1 failed" in run(win)
    assert "nested deeper" in win.jobs[0].row.info._full and os.listdir(tmp_path / "enc") == []
