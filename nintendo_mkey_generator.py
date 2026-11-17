#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import hashlib
import hmac
import struct
from pathlib import Path
import os
import sys
import subprocess

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    AES = None
    Counter = None

# ==============================================================================
# MKEY CALCULATION ENGINE
#
# Implement only the v0 variants here, which do not need region/firmware-specific
# keys. Subsequent variants require keys extracted from the firmware: they must not
# be replaced with invented static keys.
# ==============================================================================

def _crc32_reflected(data: bytes, polynomial: int) -> int:
    """Reflected CRC-32 with configurable polynomial (FFFFFFFF initialization)."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (polynomial if (crc & 1) else 0)
    return crc & 0xFFFFFFFF

def _calc_legacy_v0(month: int, day: int, inquiry: str) -> str:
    """Wii/DSi v0: CRC 0xEDB88320, XOR 0xAAAA, add 0x14C1."""
    low_four = int(inquiry, 10) % 10000
    payload = f"{month:02d}{day:02d}{low_four:04d}".encode("ascii")
    crc = _crc32_reflected(payload, 0xEDB88320)
    code = ((crc ^ 0xAAAA) + 0x14C1) % 100000
    return f"{code:05d}"

def _calc_3ds_v0(month: int, day: int, inquiry: str) -> str:
    """3DS/2DS v0: CRC 0xEDBA6320, XOR 0xAAAA, add 0x1657."""
    low_four = int(inquiry, 10) % 10000
    payload = f"{month:02d}{day:02d}{low_four:04d}".encode("ascii")
    crc = _crc32_reflected(payload, 0xEDBA6320)
    code = ((crc ^ 0xAAAA) + 0x1657) % 100000
    return f"{code:05d}"


def _calc_wiiu_v0(month: int, day: int, inquiry: str) -> str:
    """Wii U v0: CRC polynomial 0x1EDC6F41, XOR 0xAAAA, add 0x226C."""
    low_four = int(inquiry, 10) % 10000
    payload = f"{month:02d}{day:02d}{low_four:04d}".encode("ascii")
    # Wii U v0 has distinct parameters from 3DS v0. This matches the upstream
    # Wii U v0 correction (nh-server/mkey, PR #9, merged 2024-09-04).
    crc = _crc32_reflected(payload, 0x1EDC6F41)
    code = ((crc ^ 0xAAAA) + 0x226C) % 100000
    return f"{code:05d}"

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(exist_ok=True)
_DATA_README = DATA_DIR / "README.txt"
if (
    not _DATA_README.exists()
    or "wup_RR.bin" not in _DATA_README.read_text(encoding="utf-8", errors="ignore")
    or "hac_0a.bin" not in _DATA_README.read_text(encoding="utf-8", errors="ignore")
    or "Switch v4" not in _DATA_README.read_text(encoding="utf-8", errors="ignore")
    or "Does NOT require the Device ID" not in _DATA_README.read_text(encoding="utf-8", errors="ignore")
    or "10-13 Inquiry prefix" not in _DATA_README.read_text(encoding="utf-8", errors="ignore")
):
    _DATA_README.write_text(
        "KEY FILE - mkey generator\n\n"
        "3DS v1 (10-digit Inquiry, automatic recognition):\n"
        "  ctr_RR.bin - regional HMAC key, 32 bytes\n\n"
        "3DS v2 (10-digit Inquiry, version field >= 10):\n"
        "  ctr_RR_VV.bin - regional/version masterkey.bin, 64 bytes\n"
        "  ctr_aes_RR.bin - regional AES key, 16 bytes\n\n"
        "Wii U v2 (10-digit Inquiry):\n"
        "  wup_RR.bin - regional masterkey.bin, 64 bytes\n"
        "  wup_aes_RR.bin - regional AES key, 16 bytes\n"
        "  The two digits after the region are console fillers, not a key version.\n\n"
        "Switch v3 (firmware 1.0.0-7.0.1, 10-digit Inquiry):\n"
        "  hac_0a.bin / hac_0b.bin / hac_0c.bin / hac_0d.bin - HMAC key, 32 bytes; selected by 10-13 Inquiry prefix.\n"
        "  Does NOT require the Device ID.\n\n"
        "Switch v4 (firmware 8.0.0-15.0.0, 6-digit Inquiry):\n"
        "  hac_0a.bin / hac_0b.bin / hac_0c.bin / hac_0d.bin - HMAC key, 32 bytes; 10-13 Inquiry prefix and 16-digit internal hexadecimal Device ID, not the serial number.\n\n"
        "RR and VV are two-digit hexadecimal identifiers. Keys are not included: "
        "extract them exclusively from your console's firmware and do not download random files.\n",
        encoding="utf-8"
    )


def _read_key_file(filename: str, expected_size: int) -> bytes:
    """Reads a key from the data folder next to the script."""
    key_path = DATA_DIR / filename
    try:
        data = key_path.read_bytes()
    except OSError as exc:
        raise ValueError(
                            "Inquiry number invalid. Check your console Inquiry.\n\n"
                        ) from exc
    if len(data) != expected_size:
        raise ValueError(
            f"Invalid size for data/{filename}: expected {expected_size} bytes, "
            f"received {len(data)}."
        )
    return data

def _parse_3ds_inquiry(inquiry: str):
    """Extracts region and key version according to the original Inquiry format."""
    if len(inquiry) != 10 or not inquiry.isdigit():
        raise ValueError("For 3DS v1/v2 the Inquiry Number must contain exactly 10 digits.")
    # The first digit identifies the region; the next two are the version field.
    # Values < 10 identify v1, values >= 10 identify v2.
    return int(inquiry[0], 10), int(inquiry[1:3], 10)


def required_3ds_key_files(inquiry: str):
    """Returns the files required by 3DS automatic recognition."""
    if len(inquiry) != 10 or not inquiry.isdigit():
        return []
    region, key_version = _parse_3ds_inquiry(inquiry)
    if key_version < 10:
        return [f"ctr_{region:02x}.bin"]
    return [f"ctr_{region:02x}_{key_version:02x}.bin", f"ctr_aes_{region:02x}.bin"]


def _calc_3ds_v1(month: int, day: int, inquiry: str) -> str:
    """3DS 7.0.0-7.1.0: HMAC-SHA256 with regional key ctr_RR.bin."""
    region, _key_version = _parse_3ds_inquiry(inquiry)
    # In v1 the two characters after the region are NOT a key version:
    # they are filler digits derived from the console identifier. v1
    # selects the HMAC file using only the first character (region).
    key = _read_key_file(f"ctr_{region:02x}.bin", 0x20)
    payload = f"{month:02d}{day:02d}{int(inquiry):010d}".encode("ascii")
    digest = hmac.new(key, payload, hashlib.sha256).digest()
    value = struct.unpack("<I", digest[:4])[0]
    return f"{value % 100000:05d}"


def _calc_3ds_v2(month: int, day: int, inquiry: str) -> str:
    """3DS 7.2.0+: AES-128-CTR decrypts the HMAC key contained in masterkey.bin."""
    region, key_version = _parse_3ds_inquiry(inquiry)
    if key_version < 10:
        raise ValueError("Inquiry Number not compatible with v2: the key version must be at least 10.")
    if AES is None or Counter is None:
        raise ValueError("3DS v2 calculation requires PyCryptodome. Install with: pip install pycryptodome")

    masterkey = _read_key_file(f"ctr_{region:02x}_{key_version:02x}.bin", 0x40)
    aes_key = _read_key_file(f"ctr_aes_{region:02x}.bin", 0x10)
    file_region, file_version = masterkey[0], masterkey[1]
    if file_region != region or file_version != key_version:
        raise ValueError("The region/version fields of the ctr_RR_VV.bin file do not match the Inquiry Number.")

    counter_value = int.from_bytes(masterkey[0x10:0x20], "big")
    encrypted_hmac_key = masterkey[0x20:0x40]
    ctr = Counter.new(128, initial_value=counter_value)
    hmac_key = AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(encrypted_hmac_key)

    payload = f"{month:02d}{day:02d}{int(inquiry):010d}".encode("ascii")
    digest = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    value = struct.unpack("<I", digest[:4])[0]
    return f"{value % 100000:05d}"


def required_wiiu_key_files(inquiry: str):
    """Returns the necessary files for Wii U v2 (10-digit Inquiry)."""
    if len(inquiry) != 10 or not inquiry.isdigit():
        return []
    region = int(inquiry[0], 10)
    return [f"wup_{region:02x}.bin", f"wup_aes_{region:02x}.bin"]


def _calc_wiiu_v2(month: int, day: int, inquiry: str) -> str:
    """Wii U 5.0.0-5.5.5: HMAC-SHA256 with regional key decrypted via AES-CTR."""
    if len(inquiry) != 10 or not inquiry.isdigit():
        raise ValueError("For Wii U v2 the Inquiry Number must contain exactly 10 digits.")
    if AES is None or Counter is None:
        raise ValueError("Wii U v2 calculation requires PyCryptodome. Install with: pip install pycryptodome")

    # In Wii U the first digit identifies the region. The next two digits
    # are console-derived fillers and do NOT identify a key version.
    region = int(inquiry[0], 10)
    masterkey = _read_key_file(f"wup_{region:02x}.bin", 0x40)
    aes_key = _read_key_file(f"wup_aes_{region:02x}.bin", 0x10)
    file_region = masterkey[0]
    if file_region != region:
        raise ValueError(
            "The region field of the wup_RR.bin file does not match the region indicated in the Inquiry Number."
        )

    counter_value = int.from_bytes(masterkey[0x10:0x20], "big")
    encrypted_hmac_key = masterkey[0x20:0x40]
    ctr = Counter.new(128, initial_value=counter_value)
    hmac_key = AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(encrypted_hmac_key)

    payload = f"{month:02d}{day:02d}{int(inquiry):010d}".encode("ascii")
    digest = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    # Wii U interprets the first four bytes of the digest in big-endian.
    value = struct.unpack(">I", digest[:4])[0]
    return f"{value % 100000:05d}"

# Switch v3/v4 algorithm ported from Daz Jones' mkey reference implementation (AGPL-3.0-or-later):
# https://github.com/dazjo/mkey/blob/master/mkey.py
def required_switch_key_files(inquiry: str, profile: str):
    """Returns the HMAC file requested by the selected Switch profile."""
    expected_length = 10 if profile == "switch_v3" else 6 if profile == "switch_v4" else None
    if expected_length is None or len(inquiry) != expected_length or not inquiry.isdigit():
        return []
    version = int(inquiry[:2], 10)
    if not 10 <= version <= 13:
        return []
    return [f"hac_{version:02x}.bin"]


def _switch_inquiry_version(inquiry: str, expected_length: int) -> int:
    """Validates Switch format and key selector (10-13) and returns the selector."""
    if len(inquiry) != expected_length or not inquiry.isdigit():
        raise ValueError(
            f"For this Nintendo Switch profile the Inquiry must contain exactly {expected_length} digits."
        )
    version = int(inquiry[:2], 10)
    if not 10 <= version <= 13:
        raise ValueError(
            "Unrecognized Switch Inquiry: the first two digits must be between 10 and 13."
        )
    return version


def _switch_master_key_from_digest(digest: bytes) -> str:
    """Converts the HMAC output into the 8-digit Switch code."""
    value = struct.unpack("<Q", digest[:8])[0] & 0x0000FFFFFFFFFFFF
    return f"{value % 100000000:08d}"


def _calc_switch_v3(inquiry: str) -> str:
    """Switch 1.0.0-7.0.1 (v3): HMAC-SHA256 with 32-byte HAC key."""
    version = _switch_inquiry_version(inquiry, 10)
    hmac_key = _read_key_file(f"hac_{version:02x}.bin", 0x20)
    payload = f"{int(inquiry, 10) % 10000000000:010d}".encode("ascii")
    digest = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    return _switch_master_key_from_digest(digest)


def _calc_switch_v4(inquiry: str, device_id: str) -> str:
    """Switch 8.0.0-15.0.0 (v4): Iterated HMAC with internal Device ID."""
    version = _switch_inquiry_version(inquiry, 6)
    device_id = device_id.strip().replace(" ", "").replace("-", "")
    if len(device_id) != 16 or any(ch not in "0123456789abcdefABCDEF" for ch in device_id):
        raise ValueError(
            "Switch v4 requires the 16-character internal hexadecimal Device ID (not the serial number)."
        )

    hmac_key = _read_key_file(f"hac_{version:02x}.bin", 0x20)
    payload = f"{int(inquiry, 10) % 1000000:06d}".encode("ascii") + struct.pack(">I", 1)
    device_id_bytes = struct.pack("<Q", int(device_id, 16))
    hmac_key = hashlib.sha256(device_id_bytes + hmac_key).digest()

    # v4 accumulates the XOR of 10,000 concatenated HMAC-SHA256 hashes.
    output = hmac.new(hmac_key, payload, hashlib.sha256).digest()
    current = output
    for _ in range(1, 10000):
        current = hmac.new(hmac_key, current, hashlib.sha256).digest()
        output = bytes(a ^ b for a, b in zip(output, current))

    return _switch_master_key_from_digest(output)


def generate_mkey(device_profile: str, month: int, day: int, inquiry: str, additional: str = "") -> str:
    inquiry = inquiry.strip()
    additional = additional.strip()
    if device_profile in ("switch_v3", "switch_v4"):
        inquiry = inquiry.replace(" ", "").replace("-", "")

    if not inquiry.isdigit():
        raise ValueError("The Inquiry Number must contain only numeric digits.")
    import calendar
    if not 1 <= month <= 12 or not 1 <= day <= calendar.monthrange(2000, month)[1]:
        raise ValueError("The system date is not valid for the selected month.")

    if device_profile == "legacy_8":
        if len(inquiry) != 8:
            raise ValueError("For Nintendo Wii / DSi the Inquiry Number must be 8 digits.")
        return _calc_legacy_v0(month, day, inquiry)

    if device_profile == "3ds_auto":
        if len(inquiry) == 8:
            return _calc_3ds_v0(month, day, inquiry)
        if len(inquiry) == 10:
            _region, key_version = _parse_3ds_inquiry(inquiry)
            if key_version < 10:
                return _calc_3ds_v1(month, day, inquiry)
            return _calc_3ds_v2(month, day, inquiry)
        raise ValueError("Nintendo 3DS requires 8 digits (v0) or 10 digits (v1/v2).")

    if device_profile == "wiiu_auto":
        if len(inquiry) == 8:
            return _calc_wiiu_v0(month, day, inquiry)
        if len(inquiry) == 10:
            return _calc_wiiu_v2(month, day, inquiry)
        raise ValueError("Nintendo Wii U requires 8 digits (v0) or 10 digits (v2).")

    if device_profile == "switch_v3":
        if len(inquiry) != 10:
            raise ValueError("Switch firmware 1.0.0-7.0.1 (v3) requires 10 digits.")
        return _calc_switch_v3(inquiry)

    if device_profile == "switch_v4":
        if len(inquiry) != 6:
            raise ValueError("Switch firmware 8.0.0-15.0.0 (v4) requires 6 digits.")
        return _calc_switch_v4(inquiry, additional)

    raise ValueError("Unrecognized console profile.")


# ==============================================================================
# GRAPHICAL USER INTERFACE
# ==============================================================================

class MKeyApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Nintendo Master Key generator")
        self.geometry("820x810")
        self.resizable(False, False)

        self.BG_MAIN = "#121417"
        self.BG_CARD = "#1B1E24"
        self.BG_INPUT = "#252932"
        self.BG_RESULT = "#161920"
        self.BG_WARN = "#1F1A14"
        self.ACCENT = "#4F8BFF"
        self.ACCENT_HOVER = "#3B76E8"
        self.SUCCESS = "#2EA043"
        self.WARN_COLOR = "#D29922"
        self.TEXT_PRIMARY = "#F0F3F6"
        self.TEXT_SECONDARY = "#8B949E"
        self.BORDER_COLOR = "#30363D"

        self.configure(bg=self.BG_MAIN)
        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Dark.TCombobox",
            fieldbackground=self.BG_INPUT,
            background=self.BG_INPUT,
            foreground=self.TEXT_PRIMARY,
            arrowcolor=self.TEXT_PRIMARY,
            bordercolor=self.BORDER_COLOR,
            lightcolor=self.BG_INPUT,
            darkcolor=self.BG_INPUT,
            padding=6
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", self.BG_INPUT)],
            selectbackground=[("readonly", self.BG_INPUT)],
            selectforeground=[("readonly", self.TEXT_PRIMARY)]
        )
        self.option_add("*TCombobox*Listbox.background", self.BG_INPUT)
        self.option_add("*TCombobox*Listbox.foreground", self.TEXT_PRIMARY)
        self.option_add("*TCombobox*Listbox.selectBackground", self.ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")
        self.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))

    def _build_ui(self):
        # --- HEADER ---
        header_frame = tk.Frame(self, bg=self.BG_MAIN)
        header_frame.pack(fill="x", padx=36, pady=(20, 10))

        title_row = tk.Frame(header_frame, bg=self.BG_MAIN)
        title_row.pack(anchor="w")

        tk.Label(
            title_row, text="Nintendo Master Key generator", bg=self.BG_MAIN, fg=self.TEXT_PRIMARY,
            font=("Segoe UI", 18, "bold")
        ).pack(side="left")

        tk.Label(
            header_frame,
            text="Wii / DSi / 3DS / 2DS / Wii U / Switch — Parental Controls Master Key",
            bg=self.BG_MAIN, fg=self.TEXT_SECONDARY, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=(2, 0))

        # --- MAIN CARD ---
        card = tk.Frame(
            self, bg=self.BG_CARD, highlightbackground=self.BORDER_COLOR,
            highlightthickness=1, padx=26, pady=18
        )
        card.pack(fill="both", expand=True, padx=36, pady=(0, 16))

        # 1. DEVICE TYPE
        self._create_label(card, "Console", "Select the console")
        self.devices_map = {
            "3DS / 2DS / New 3DS": "3ds_auto",
            "Wii U": "wiiu_auto",
            "Wii": "legacy_8",
            "DSi / DSi XL": "legacy_8",
            "Switch / Lite / OLED (ver 1.0.0 - 7.0.1)": "switch_v3",
            "Switch / Lite / OLED (ver 8.0.0 - 15.0.0)": "switch_v4",
        }
        self.device_var = tk.StringVar(value="")
        self.device_combo = ttk.Combobox(
            card, textvariable=self.device_var, values=list(self.devices_map.keys()),
            state="readonly", style="Dark.TCombobox", font=("Segoe UI", 10)
        )
        self.device_combo.pack(fill="x", pady=(4, 12))
        self.device_combo.bind("<<ComboboxSelected>>", self._on_device_change)

        # 2. SYSTEM DATE (hidden for Nintendo Switch)
        self.date_container = tk.Frame(card, bg=self.BG_CARD)
        # Shown only after a console type has been selected.
        self._create_label(
            self.date_container,
            "System date",
            "Select the date set on your console"
        )
        date_frame = tk.Frame(self.date_container, bg=self.BG_CARD)
        date_frame.pack(fill="x", pady=(4, 12))

        self.months = [
            "01 - January", "02 - February", "03 - March", "04 - April",
            "05 - May", "06 - June", "07 - July", "08 - August",
            "09 - September", "10 - October", "11 - November", "12 - December"
        ]
        now = datetime.now()
        self.month_var = tk.StringVar(value=self.months[now.month - 1])
        self.day_var = tk.StringVar(value=f"{now.day:02d}")

        tk.Label(date_frame, text="Month", bg=self.BG_CARD, fg=self.TEXT_SECONDARY,
                 font=("Segoe UI", 8)).pack(side="left", padx=(0, 5))
        self.month_combo = ttk.Combobox(
            date_frame, textvariable=self.month_var, values=self.months,
            state="readonly", style="Dark.TCombobox", font=("Segoe UI", 10), width=19
        )
        self.month_combo.pack(side="left", padx=(0, 14))
        tk.Label(date_frame, text="Day", bg=self.BG_CARD, fg=self.TEXT_SECONDARY,
                 font=("Segoe UI", 8)).pack(side="left", padx=(0, 5))
        self.day_combo = ttk.Combobox(
            date_frame, textvariable=self.day_var,
            values=[f"{d:02d}" for d in range(1, 32)],
            state="readonly", style="Dark.TCombobox", font=("Segoe UI", 10), width=6
        )
        self.day_combo.pack(side="left")
        self._month_touched = False
        self._day_touched = False
        self.month_combo.bind("<<ComboboxSelected>>", self._on_date_selected)
        self.day_combo.bind("<<ComboboxSelected>>", self._on_date_selected)

        # 3. ADDITIONAL DATA (shown automatically for 6-digit Switch v4)
        self.device_id_container = tk.Frame(card, bg=self.BG_CARD)
        self._create_label(
            self.device_id_container,
            "Device ID",
            "Enter the 16-character hexadecimal internal Device ID (0-9, A-F), not the console serial number"
        )
        self.additional_var = tk.StringVar()
        self.additional_var.trace_add("write", self._refresh_generate_button)
        self.additional_entry = tk.Entry(
            self.device_id_container, textvariable=self.additional_var,
            bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground=self.TEXT_PRIMARY,
            relief="flat", font=("Consolas", 11),
            highlightbackground=self.BORDER_COLOR, highlightthickness=1
        )
        self.additional_entry.pack(fill="x", ipady=6, pady=(4, 12))

        # 4. INQUIRY NUMBER
        self.inquiry_container = tk.Frame(card, bg=self.BG_CARD)
        # Shown only after a console type has been selected.
        self.inquiry_hint_var = tk.StringVar(value="Enter the numeric Inquiry Number shown on your console")
        self._create_label(self.inquiry_container, "Inquiry number", "Enter the code shown on your console")
        tk.Label(
            self.inquiry_container, textvariable=self.inquiry_hint_var,
            bg=self.BG_CARD, fg=self.TEXT_SECONDARY, font=("Segoe UI", 8)
        ).pack(anchor="w", pady=(2, 0))
        self.inquiry_var = tk.StringVar()
        self.inquiry_var.trace_add("write", self._refresh_generate_button)
        self.inquiry_entry = tk.Entry(
            self.inquiry_container, textvariable=self.inquiry_var,
            bg=self.BG_INPUT, fg=self.TEXT_PRIMARY, insertbackground=self.TEXT_PRIMARY,
            relief="flat", font=("Consolas", 12, "bold"),
            highlightbackground=self.BORDER_COLOR, highlightthickness=1
        )
        self.inquiry_entry.pack(fill="x", ipady=7, pady=(4, 14))
        self.inquiry_entry.bind("<Return>", lambda e: self._calculate())

        # GENERATE BUTTON
        self.gen_btn = tk.Button(
            card, text="Generate Master Key", command=self._calculate,
            bg="#343A40", fg="#FFFFFF", activebackground="#343A40",
            activeforeground="#FFFFFF", relief="flat", cursor="no",
            disabledforeground="#8B949E", font=("Segoe UI", 10, "bold"),
            pady=9, state="disabled"
        )
        self.gen_btn.pack(fill="x", pady=(0, 2))

        # --- RESULT BOX ---
        res_box = tk.Frame(
            self, bg=self.BG_RESULT, highlightbackground=self.BORDER_COLOR,
            highlightthickness=1, padx=14, pady=12
        )
        res_box.pack(fill="x", padx=36, pady=(0, 20))

        res_top = tk.Frame(res_box, bg=self.BG_RESULT)
        res_top.pack(fill="x")
        tk.Label(
            res_top, text="MASTER KEY", bg=self.BG_RESULT,
            fg=self.TEXT_SECONDARY, font=("Segoe UI", 8, "bold")
        ).pack(side="left")

        self.generated_code = None
        self.result_var = tk.StringVar(value="— — — — — —")
        self.result_lbl = tk.Label(
            res_box, textvariable=self.result_var, bg=self.BG_RESULT,
            fg=self.TEXT_PRIMARY, font=("Consolas", 22, "bold"), cursor="arrow"
        )
        self.result_lbl.pack(pady=(5, 0))
        self.result_lbl.bind("<Button-1>", self._copy_code)

        self.copy_hint_var = tk.StringVar(value="")
        self.copy_hint_lbl = tk.Label(
            res_box, textvariable=self.copy_hint_var, bg=self.BG_RESULT,
            fg=self.TEXT_SECONDARY, font=("Segoe UI", 8)
        )
        self.copy_hint_lbl.pack(pady=(3, 0))


        # --- WARNING BOX ---
        warn_box = tk.Frame(
            self, bg=self.BG_WARN, highlightbackground=self.WARN_COLOR,
            highlightthickness=1, padx=16, pady=12
        )
        warn_box.pack(fill="x", padx=36, pady=(0, 20))

        tk.Label(
            warn_box, text="⚠️ Summary of console and firmware ver. requirements:", bg=self.BG_WARN,
            fg=self.WARN_COLOR, font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        warn_text = (
            "• Wii / DSi: 8 digits Inquiry only.\n"
            "• Wii U (ver 1.0.0 - 4.1.0): 8 digits Inquiry.\n"
            "• Wii U (ver 5.0.0 - 5.5.6): 10 digits Inquiry.\n"
            "• 3DS / 2DS (ver 1.0.0 - 7.1.0): 8 digits Inquiry.\n"
            "• 3DS / 2DS (ver 7.2.0 - 11.17.0): 10 digits Inquiry.\n"
            "• Switch (ver 1.0.0 - 7.0.1): 10-digit Inquiry.\n"
            "• Switch (ver 8.0.0 - 15.0.0): 6-digit Inquiry + 16-digit internal hexadecimal Device ID.\n"
            "• Switch 15.0.1+ & Switch 2: NOT SUPPORTED; use the official Nintendo procedure."
        )
        tk.Label(
            warn_box, text=warn_text, bg=self.BG_WARN, fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 9), justify="left"
        ).pack(anchor="w", pady=(3, 0))

        data_tools = tk.Frame(warn_box, bg=self.BG_WARN)
        data_tools.pack(fill="x", pady=(8, 0))
        


        self._on_device_change()

    def _create_label(self, parent, title, hint):
        row = tk.Frame(parent, bg=self.BG_CARD)
        row.pack(fill="x")
        tk.Label(
            row, text=title, bg=self.BG_CARD, fg=self.TEXT_PRIMARY,
            font=("Segoe UI", 9, "bold")
        ).pack(side="left")
        tk.Label(
            row, text=f"• {hint}", bg=self.BG_CARD, fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 8)
        ).pack(side="left", padx=(6, 0), pady=(1, 0))

    def _on_date_selected(self, event=None):
        if event.widget is self.month_combo:
            self._month_touched = True
        elif event.widget is self.day_combo:
            self._day_touched = True
        self._refresh_generate_button()

    def _refresh_generate_button(self, *_args):
        profile = self.devices_map.get(self.device_var.get())
        ready = profile is not None
        if profile is not None:
            inquiry = self.inquiry_var.get().strip().replace(" ", "").replace("-", "")
            if profile == "legacy_8":
                ready = len(inquiry) == 8 and inquiry.isdigit()
            elif profile in ("3ds_auto", "wiiu_auto"):
                ready = len(inquiry) in (8, 10) and inquiry.isdigit()
            elif profile == "switch_v3":
                ready = len(inquiry) == 10 and inquiry.isdigit() and inquiry[:2] in ("10", "11", "12", "13")
            elif profile == "switch_v4":
                ready = len(inquiry) == 6 and inquiry.isdigit() and inquiry[:2] in ("10", "11", "12", "13")
                device_id = self.additional_var.get().strip().replace(" ", "").replace("-", "")
                ready = ready and len(device_id) == 16 and all(c in "0123456789abcdefABCDEF" for c in device_id)

            # Month and day never affect whether Generate is enabled.

        if ready:
            self.gen_btn.configure(state="normal", cursor="hand2", bg=self.ACCENT,
                                   activebackground=self.ACCENT_HOVER)
        else:
            self.gen_btn.configure(state="disabled", cursor="no", bg="#343A40",
                                   activebackground="#343A40")

    def _on_device_change(self, event=None):
        selected = self.device_var.get()
        profile = self.devices_map.get(selected)

        # Keep every field hidden until the user selects a console.
        self.date_container.pack_forget()
        self.device_id_container.pack_forget()
        self.inquiry_container.pack_forget()

        if profile is None:
            self.generated_code = None
            self.result_var.set("— — — — — —")
            self.copy_hint_var.set("")
            self._refresh_generate_button()
            return

        switch_profile = profile in ("switch_v3", "switch_v4")
        inquiry_hints = {
            "legacy_8": "Enter exactly 8 digits.",
            "3ds_auto": "Enter 8 digits or 10 digits.",
            "wiiu_auto": "Enter 8 digits or 10 digits.",
            "switch_v3": "Enter exactly 10 digits.",
            "switch_v4": "Enter exactly 6 digits.",
        }
        self.inquiry_hint_var.set(inquiry_hints[profile])
        self._month_touched = False
        self._day_touched = False

        # Date is required for every supported console except Switch.
        if switch_profile:
            self.month_combo.configure(state="disabled")
            self.day_combo.configure(state="disabled")
        else:
            self.month_combo.configure(state="readonly")
            self.day_combo.configure(state="readonly")
            self.date_container.pack(fill="x", before=self.gen_btn)

        # Only Switch v4 asks for the internal Device ID.
        if profile == "switch_v4":
            self.device_id_container.pack(fill="x", before=self.gen_btn)

        # Inquiry is shown for every selected console.
        self.inquiry_container.pack(fill="x", before=self.gen_btn)

        self.generated_code = None
        placeholder_count = 8 if switch_profile else 6
        self.result_var.set(" ".join(["—"] * placeholder_count))
        self.result_lbl.configure(
            fg=self.TEXT_PRIMARY,
            font=("Consolas", 22, "bold"),
            cursor="arrow"
        )
        self.copy_hint_var.set("")
        self._refresh_generate_button()

    def _calculate(self):
        selected = self.device_var.get()
        profile = self.devices_map.get(selected)
        if profile is None:
            messagebox.showwarning("Warning", "Select a console type first.")
            return
        month = int(self.month_var.get().split(" - ")[0])
        day = int(self.day_var.get())
        inquiry = self.inquiry_var.get()
        additional = self.additional_var.get()

        try:
            required = []
            if profile == "3ds_auto" and len(inquiry.strip()) == 10:
                required = required_3ds_key_files(inquiry.strip())
            elif profile == "wiiu_auto" and len(inquiry.strip()) == 10:
                required = required_wiiu_key_files(inquiry.strip())
            elif profile in ("switch_v3", "switch_v4"):
                normalized_inquiry = inquiry.strip().replace(" ", "").replace("-", "")
                required = required_switch_key_files(normalized_inquiry, profile)
            missing = [name for name in required if not (DATA_DIR / name).is_file()]
            if missing:
                raise ValueError(
                    "Inquiry number invalid. Check your console Inquiry.\n\n"
                )
            master_key = generate_mkey(profile, month, day, inquiry, additional)
            self.generated_code = master_key
            self.result_var.set("".join(master_key))
            self.result_lbl.configure(fg=self.SUCCESS, font=("Consolas", 28, "bold"), cursor="hand2")
            self.copy_hint_var.set("Click on the Master Key to copy it")
        except ValueError as err:
            self.generated_code = None
            self.result_var.set("ERROR")
            self.result_lbl.configure(fg="#F85149", font=("Consolas", 28, "bold"), cursor="arrow")
            self.copy_hint_var.set("")
            messagebox.showwarning("Warning", str(err))

    def _open_data_folder(self):
        DATA_DIR.mkdir(exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(DATA_DIR))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(DATA_DIR)])
            else:
                subprocess.Popen(["xdg-open", str(DATA_DIR)])
        except Exception as exc:
            messagebox.showerror("Data folder", f"Could not open the folder:\n{DATA_DIR}\n\n{exc}")

    def _copy_code(self, event=None):
        if not self.generated_code:
            return
        self.clipboard_clear()
        self.clipboard_append(self.generated_code)
        self.copy_hint_var.set("Copied to clipboard!")


if __name__ == "__main__":
    app = MKeyApp()
    app.mainloop()