# VirtualPyDetector (VPD) 🔍

[![Python 3.13.2+](https://img.shields.io/badge/python-3.13.2+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Donate](https://img.shields.io/badge/Donate-EasyDonate-green)](https://easydonate.app/paopun2060)


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

```python
from VirtualPyDetector import VirtualPyDetector

VPD = VirtualPyDetector()

if VPD.venv_active:
    print("Virtual environment or debugger detected!")
else:
    print("No virtual environment or debugger detected.")
