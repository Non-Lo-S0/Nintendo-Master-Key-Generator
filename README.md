# Nintendo Master Key Generator

A desktop application written in Python to generate **Parental Controls Master Keys** for Nintendo consoles, including Wii, DSi, 3DS, 2DS, Wii U and Nintendo Switch.

The application features a simple graphical interface built with Tkinter and automatically selects the appropriate calculation algorithm based on the selected console and Inquiry Number format.

## Features

- **Multi-console support:** Wii, DSi, 3DS, 2DS, Wii U and Nintendo Switch.
- **Automatic algorithm detection:** Selects the appropriate calculation method based on the console profile and Inquiry Number.
- **Modern GUI:** Dark-themed interface with a clean and intuitive design.
- **Clipboard integration:** Click the generated Master Key to copy it instantly.
- **External key support:** Reads required cryptographic keys from a local `data` folder.
- **Input validation:** Checks Inquiry Numbers, Device IDs and required key files before generating a code.
- **No internet connection required:** All calculations are performed locally.

## Supported Consoles and Firmware

| Console | Firmware | Inquiry Number | Device ID | Additional Information |
|---|---|---|---|---|
| Wii / DSi | All versions | 8 digits | No | v0 algorithm |
| 3DS / 2DS | 1.0.0 – 7.1.0 | 8 digits | No | v0 algorithm |
| 3DS / 2DS | 7.0.0 – 7.1.0 | 10 digits | No | v1 algorithm |
| 3DS / 2DS | 7.2.0 – 11.17.0 | 10 digits | No| v2 algorithm |
| Wii U | 1.0.0 – 4.1.0 | 8 digits | No | v0 algorithm |
| Wii U | 5.0.0 – 5.5.6 | 10 digits | No | v2 algorithm |
| Switch / Lite / OLED | 1.0.0 – 7.0.1 | 10 digits | No | v3 algorithm |
| Switch / Lite / OLED | 8.0.0 – 15.0.0 | 6 digits | 16 hex characters | v4 algorithm |

**Not supported:**
- Nintendo Switch firmware 15.0.1 and later.
- Nintendo Switch 2.

For unsupported systems, use Nintendo's official recovery procedure.

## Requirements

- Python 3.8 or later.
- Tkinter (usually included with Python).
- PyCryptodome (required for 3DS v2 and Wii U v2 calculations).

### Install dependencies

```bash
pip install pycryptodome
```

PyCryptodome is optional for profiles that do not require AES-CTR decryption.

## Installation

1. Clone or download this repository.

```bash
git clone https://github.com/your-username/nintendo-mkey-generator.git
```

2. Navigate to the project directory.

```bash
cd nintendo-mkey-generator
```

3. Install the required dependency.

```bash
pip install pycryptodome
```

4. Run the application.

```bash
python nintendo_mkey_generator.py
```

## Key Files Configuration

Some calculation methods require cryptographic keys extracted from the console's firmware.

The application automatically creates a `data` directory next to the Python script and generates a `README.txt` file describing the required key files.

### Nintendo 3DS / 2DS

**v1 (10-digit Inquiry Number):**

```text
data/
└── ctr_RR.bin
```

- `ctr_RR.bin`: 32-byte regional HMAC key.

**v2 (10-digit Inquiry Number):**

```text
data/
├── ctr_RR_VV.bin
└── ctr_aes_RR.bin
```

- `ctr_RR_VV.bin`: 64-byte regional/version master key.
- `ctr_aes_RR.bin`: 16-byte regional AES key.

### Nintendo Wii U

**v2 (10-digit Inquiry Number):**

```text
data/
├── wup_RR.bin
└── wup_aes_RR.bin
```

- `wup_RR.bin`: 64-byte regional master key.
- `wup_aes_RR.bin`: 16-byte regional AES key.

### Nintendo Switch

**v3 and v4:**

```text
data/
├── hac_0a.bin
├── hac_0b.bin
├── hac_0c.bin
└── hac_0d.bin
```

- Each file contains a 32-byte HMAC key.
- The required key is selected automatically using the first two digits of the Inquiry Number (10–13).
- Switch v3 does not require a Device ID.
- Switch v4 requires the console's internal 16-character hexadecimal Device ID.

**Important:** `RR` and `VV` represent two-digit hexadecimal identifiers. The required cryptographic keys are not included in this repository. Extract them exclusively from your own console's firmware. Do not use randomly downloaded or unverified key files.

## How to Use

1. Launch the application.
2. Select your Nintendo console and supported firmware profile.
3. Enter the system date when requested.
4. Enter the Inquiry Number displayed by your console.
5. For Switch firmware 8.0.0–15.0.0, also enter the internal Device ID.
6. Click **Generate Master Key**.
7. Click the generated code to copy it to your clipboard.

## Calculation Methods

The application implements different algorithms depending on the console and firmware generation.

| Profile | Algorithm |
|---|---|
| Wii / DSi v0 | Reflected CRC-32 |
| 3DS v0 | Reflected CRC-32 |
| 3DS v1 | HMAC-SHA256 |
| 3DS v2 | AES-128-CTR + HMAC-SHA256 |
| Wii U v0 | Reflected CRC-32 |
| Wii U v2 | AES-128-CTR + HMAC-SHA256 |
| Switch v3 | HMAC-SHA256 |
| Switch v4 | Iterated HMAC-SHA256 |

## Troubleshooting

**Missing key file**

Make sure the required files are present in the `data` directory and have the correct filenames.

**Invalid key file size**

Verify that the key file matches the expected size:

- HMAC keys: 32 bytes.
- AES keys: 16 bytes.
- Master key files: 64 bytes.

**Invalid Inquiry Number**

Check that the Inquiry Number has the correct number of digits for your selected console and firmware profile.

**PyCryptodome error**

Install the missing dependency:

```bash
pip install pycryptodome
```

**Switch v4 Device ID error**

Make sure you enter the 16-character hexadecimal internal Device ID, not the console serial number.

## Disclaimer

This project is provided for educational and interoperability purposes.

It is an independent, unofficial tool and is not affiliated with, endorsed by, or associated with Nintendo.

Nintendo and its respective console names are trademarks of Nintendo Co., Ltd.

Use this software only with consoles and cryptographic material you are authorized to access. The developer assumes no responsibility for misuse or damage resulting from the use of this software.
