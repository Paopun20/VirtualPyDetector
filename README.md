# VirtualPyDetector (VPD) 🔍

[![Python 3.13.2+](https://img.shields.io/badge/python-3.13.2+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Repo stars](https://img.shields.io/github/stars/Paopun20/VirtualPyDetector?style=social)](https://github.com/Paopun20/VirtualPyDetector)


VirtualPyDetector (VPD) is a Python library designed to detect virtualized and sandboxed environments.  It uses a multi-layered approach, combining several techniques to improve detection accuracy.  This tool is useful for security analysis, malware research, and other applications requiring robust environment detection.

**Currently, VPD focuses on detecting:**

* Virtual Machines (VMs)
* Debuggers

**Future development may include detection of:**

* Sandboxes (Currently, limited checks are present)


## Features ✨

* **Multi-Layered Analysis:** Employs various detection techniques (see below) for enhanced accuracy.
* **Cross-Platform Compatibility:**  Supports Windows, macOS, and Linux (with varying levels of completeness).  Some features may not function on all platforms.
* **Simple API:** Easy to integrate into existing Python projects.


## Installation 📦

Currently, the simplest way to use VirtualPyDetector is to copy `VirtualPyDetector.py` into your project directory.  (Future versions may offer a more formal installation method via pip).

## Usage 🚀

Going to your project directory, you can import and use the library like this:

```python
from VirtualPyDetector import VirtualPyDetector

detector = VirtualPyDetector()

if detector.is_virtualized():
    print("Virtualized environment detected!")
else:
    print("No virtualization detected.")

if detector.is_debugged():
    print("Debugger detected!")
else:
    print("No debugger detected.")
```

or see this file in [example.py](example.py) for more examples.

## Detection Techniques 🛠️

VPD uses a combination of the following techniques:

*   **CPU Information:** Checks for known virtual machine CPU vendor strings.
*   **MAC Address Analysis:** Examines MAC addresses for known virtual machine OUI prefixes.
*   **Device Driver Enumeration:** Identifies known virtual machine device drivers.
*   **System Processes:** Checks for known virtual machine processes.
*   **Timing Anomalies:** Detects timing differences that may indicate virtualization.
*   **Debugger Detection:** Checks for the presence of debuggers.
*   **Registry Analysis:** Checks for known virtual machine registry keys.
*   **File System Analysis:** Checks for known virtual machine files.

## Limitations ⚠️

*   **Evasion:** Advanced virtualization environments may be able to evade detection.
*   **False Positives:**  It's possible to get false positives in some cases.
*   **Platform Specificity:** Some detection methods are platform-specific.
*   **Ongoing Development:** This project is under active development, and detection methods may change.

## Contributing 🤝

Contributions are welcome! Please feel free to submit pull requests or open issues to discuss potential improvements.

## License 📜

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
