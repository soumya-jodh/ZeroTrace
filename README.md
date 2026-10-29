# ZeroTrace-OS - Secure Data Sanitization

ZeroTrace-OS is an offline-oriented, hardware-aware data sanitization
project for HDD, SATA SSD, and NVMe drives. It combines device
discovery, pre-wipe safety checks, device-specific sanitization,
post-operation verification, drive-health assessment, audit logging, and
cryptographically signed certificates.

> **Warning:** Sanitization is destructive and may permanently erase
> data. Use only on devices you own or are authorized to sanitize. Test
> on disposable virtual disks or dedicated test hardware. Never
> experiment on your host OS disk or a drive containing important data.

## Features

-   Discovers block devices and reads available device metadata.
-   Performs preflight checks and requires explicit target confirmation.
-   Routes devices according to media type, capabilities, and state.
-   Uses `nwipe` for HDD overwrite workflows.
-   Uses supported ATA Secure Erase operations through `hdparm` for SATA
    SSDs.
-   Uses supported NVMe Sanitize actions through `nvme-cli`.
-   Verifies results using evidence appropriate to the selected method.
-   Calculates an advisory drive reusability score from available
    SMART/health indicators.
-   Creates audit evidence using SHA-256 and Ed25519.
-   Generates signed JSON evidence and PDF certificates, with QR support
    where configured.
-   Provides a local dashboard for device selection, progress,
    verification, certificates, and audit history.

## Workflow

``` text
Boot / Initialize
       |
Device Discovery
       |
Safety & Preflight ---- failure ----> Abort with reason
       |
Capability Detection
       |
Sanitization Router
   /       |        \
 HDD    SATA SSD    NVMe
   \       |        /
Post-Sanitization Verification
       |
Health & Reusability Assessment
       |
Audit Record -> SHA-256 -> Ed25519 Signature
       |
Signed JSON + PDF/QR Certificate
       |
Dashboard / Audit History
```

## Technology Stack

-   **Language:** Python 3
-   **Dashboard/API:** Flask
-   **Operating system:** Linux
-   **HDD:** `nwipe`
-   **SATA SSD:** `hdparm`
-   **NVMe:** `nvme-cli`
-   **Device health:** `smartmontools`
-   **Discovery and verification utilities:** `util-linux`, `udev`,
    `file`, `coreutils`
-   **Cryptography:** SHA-256 and Ed25519 (`cryptography`)
-   **Certificates:** ReportLab and `qrcode`

## Requirements and Setup

Use a supported Ubuntu or Debian-based Linux environment. Some commands
require root privileges. Actual ATA Secure Erase and NVMe Sanitize
support depends on the device, controller, firmware, and current
security state.

### Install system utilities

``` bash
sudo apt update
sudo apt install -y hdparm nvme-cli smartmontools nwipe util-linux udev file coreutils
```

### Install Python dependencies

From the project root, use a virtual environment if desired, then run:

``` bash
python3 -m pip install -r requirements.txt
```

## Running the Project

### 1. Start the Flask dashboard

From the project root, install the Python dependencies:

``` bash
python3 -m pip install -r requirements.txt
```

Start the dashboard using the provided launcher:

``` bash
sudo bash run_ui.sh
```

Alternatively, start the Flask app directly:

``` bash
sudo python3 ui/app.py
```

Keep the terminal open while the application runs. Open the local
address printed in the terminal in your browser. 

Use the dashboard to discover and select a device, review warnings, run
preflight checks, monitor sanitization progress, inspect verification
results, and access certificates or audit history. Available controls
may vary by project version.

### 2. Use the command-line engine

To view available commands:

``` bash
python3 app/engine.py --help
```

Common inspection and preflight commands in the current development
workflow are:

``` bash
sudo python3 app/engine.py capabilities /dev/sdX
sudo python3 app/engine.py preflight /dev/sdX
```

For an NVMe device, use its actual namespace path, for example:

``` bash
sudo python3 app/engine.py capabilities /dev/nvme0n1
sudo python3 app/engine.py preflight /dev/nvme0n1
```

Replace example paths only after checking the device list carefully:

``` bash
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,TRAN
```

**Never copy a device path blindly.** Run a destructive operation only
after confirming the target identity and size and ensuring that the
device contains no data you need.

Do not expose a privileged Flask sanitization interface to an untrusted
network. Run it locally on a trusted test machine and stop the server
when finished.

## Safe Testing

1.  Prefer a disposable VirtualBox virtual disk or dedicated spare
    drive.
2.  Confirm that the test disk is separate from the VM's root/system
    disk.
3.  Review `lsblk` output and run capability detection and preflight
    checks.
4.  Confirm the selected device identity and size before execution.
5.  Review verification status and audit evidence after the operation.
6.  Do not test ATA Secure Erase or NVMe Sanitize on production or
    personal storage.

## Security Notes and Limitations

-   A successful command exit alone does not prove every sanitization
    requirement has been met.
-   Verification must match the selected sanitization method and device.
-   Absence of filesystem signatures alone is not conclusive proof that
    all data was sanitized.
-   ATA Secure Erase may be blocked by frozen/locked states or
    unsupported firmware behavior.
-   NVMe actions and status fields vary by controller and firmware.
-   The SMART-based reusability score is advisory, not a guarantee of
    future reliability.
-   Protect the Ed25519 private signing key; verification depends on
    trusting the corresponding public key.

## Status

ZeroTrace-OS is an academic development project. The current
implementation includes a Python engine, device-specific sanitization
workflows, verification and audit logic, certificate generation, and a
local dashboard. Hardware-dependent behavior must be validated on
compatible test devices before production use.

## Future Enhancements

-   Support additional storage interfaces.
-   Improve method-specific verification and reporting.
-   Refine the drive reusability heuristic.
-   Add batch sanitization and consolidated audit reports.
-   Improve bootable live-USB packaging and usability.
