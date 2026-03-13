# I2C-Printer-Cartridge
## Firmware Section — Buffer Overflow & DoS Attacks

This is the firmware contribution to the paper. It covers two attacks implemented in the cartridge firmware and how the printer firmware detects them.

---

## Files

```
firmware/
├── cartridge_firmware.ino   # Implements the two attacks
└── printer_firmware.ino     # Detects and logs both attacks
paper/
└── attack_documentation.docx
```

---

## Attack 1 — Buffer Overflow

The cartridge lies about `frame_len` in the header — claims 64 bytes when the printer's buffer is only 48. The printer trusts this value, reads 64 bytes, and overwrites `auth_flag` in adjacent memory. The CRC passes because the cartridge recomputes it over the forged payload.

**What the firmware does:**
- Cartridge sends `frame_len=64` with a valid forged CRC over the poisoned 32-byte chunk
- Printer reads 64 bytes into a 48-byte buffer — 16 bytes overflow into `auth_flag`
- `auth_flag` gets set to `0xAD`, triggering service mode unlock in the printer

**The core problem:** CRC is recomputable by anyone. It cannot authenticate intent.

---

## Attack 2 — Denial of Service

The cartridge sends `page_count=255, frame_len=255` in the header with a valid CRC. The printer enters a loop of 2,040+ chunk reads, blocking all other operations until power-cycled.

**What the firmware does:**
- Cartridge sends the malicious header with correctly computed CRC
- Printer loops through 255 pages × 8 chunks each, receiving junk data with valid CRCs
- Printer is fully locked — no jobs, no UI, no network response

**The core problem:** CRC validates that bytes arrived intact. It cannot validate whether field values are safe to act on.

---

## Why CRC Fails for Both

| | Buffer Overflow | DoS |
|---|---|---|
| CRC outcome | PASS — attacker forged it | PASS — computed over junk |
| What CRC missed | Payload was malicious | Field values were unsafe |
| Actual fix needed | HMAC + bounds check on `frame_len` | Bounds check on `page_count` and `frame_len` |

---
