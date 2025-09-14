
# vinetalk-aibox-dump

Firmware dump and teardown notes for the VineTalk "AI box" necklace device.

- **SoC:** ESP32‑C3 (QFN32, rev v0.4)  
- **Flash:** 8 MB  
- **USB:** USB‑Serial/JTAG (enumerates as COM3 on Windows)  
- **Security state:** Secure Boot **disabled**, Flash Encryption **disabled** (see `out/logs/espefuse_summary.txt`)

## What’s in here

- `bins/` – raw flash artifacts
  - `bootloader.bin` (0x000000–0x007FFF)
  - `partitions.bin` (0x008000–0x008FFF)
  - `nvs.bin`, `otadata.bin`, `phy_init.bin`, `storage.bin`
  - `ota_0.bin`, `ota_1.bin`
  - `dump.bin` – full 8 MB flash (optional to publish)
- `out/` – post‑processing outputs (strings, hits with context, endpoint/domain lists, PEMs, hashes, reports)
- `ESPTOOL_EXE/` and `STRING_EXE/` – Windows helpers (esptool + Sysinternals strings)
- `analyze.ps1`, `strings_hardcore.ps1`, `decode_b64_json.ps1` – analysis scripts (Windows/PowerShell)

## Flash map (from `partitions.bin`)

| name      | type | subtype | offset     | size       |
| --------- | ---- | ------- | ---------- | ---------- |
| nvs       | data | nvs     | 0x00009000 | 0x00004000 |
| otadata   | data | ota     | 0x0000D000 | 0x00002000 |
| phy\_init | data | phy     | 0x0000F000 | 0x00001000 |
| storage   | data | nvs     | 0x00010000 | 0x000F0000 |
| ota\_0    | app  | ota\_0  | 0x00100000 | 0x002EE000 |
| ota\_1    | app  | ota\_1  | 0x003F0000 | 0x002EE000 |

*(Bootloader at 0x000000, 32 KB; partition table at 0x0008000, 4 KB).*

## How the dump was made (Windows)

```powershell
# detect flash size
esptool.exe --port COM3 flash_id

# full dump (8 MB)
esptool.exe --port COM3 read-flash 0 0x800000 dump.bin

# per-partition reads
esptool.exe --port COM3 read-flash 0x00000000 0x00008000 bootloader.bin
esptool.exe --port COM3 read-flash 0x00008000 0x00001000 partitions.bin
esptool.exe --port COM3 read-flash 0x00009000 0x00004000 nvs.bin
esptool.exe --port COM3 read-flash 0x0000D000 0x00002000 otadata.bin
esptool.exe --port COM3 read-flash 0x0000F000 0x00001000 phy_init.bin
esptool.exe --port COM3 read-flash 0x00010000 0x000F0000 storage.bin
esptool.exe --port COM3 read-flash 0x00100000 0x002EE000 ota_0.bin
esptool.exe --port COM3 read-flash 0x003F0000 0x002EE000 ota_1.bin
````

## Quick findings

* Cloud endpoints present in firmware/NVS:

  * `api-us.vinetalk.ai`
  * `socket-us.vinetalk.ai`
* A root CA (**DigiCert Global Root G2**) is embedded in the app image.
* No MACs, IPv4 addresses, JWTs, or e‑mails turned up in the current string scans.

## License

Research dump and notes for interoperability/security research. Original firmware belongs to its respective owner.
