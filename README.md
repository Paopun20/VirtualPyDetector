# VirtualPyDetector [ VPD ] 🔍

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Donate](https://img.shields.io/badge/Donate-EasyDonate-green)](https://easydonate.app/paopun2060)

Advanced virtualization and sandbox environment detection system with multi-layered analysis.

## Features ✨

- **Hardware Fingerprinting**  
  Detect VM-specific hardware signatures
- **Hypervisor Detection**  
  Identify presence of VMware, VirtualBox, QEMU, Hyper-V
- **Timing Analysis**  
  CPU instruction timing checks using RDTSC
- **Forensic Artifact Scanning**  
  Filesystem and registry artifact detection
- **Behavioral Analysis**  
  Memory usage patterns and uptime checks
- **Anti-Evasion Techniques**  
  Detect hidden processes and core count discrepancies
- **Multi-Platform Support**  
  Windows, Linux, and macOS compatibility

## Installation 📦

```bash
pip install pip@git+https://github.com/Paopun20/VirtualPyDetector.git
```

## Usage 🚀

### Python Integration
```python
from VirtualPyDetector import VirtualPyDetector

detector = VirtualPyDetector()
if detector.is_virtual_environment:
    print("Virtual environment detected!")
else:
    print("Native environment")
```

## Detection Methods 🛡️

| **Technique**               | **Windows** | **Linux**       | **macOS**       | **Description**                                                                 |
|-----------------------------|-------------|-----------------|-----------------|---------------------------------------------------------------------------------|
| **Hardware Fingerprinting** | ✔           | ✔               | ✔               | Detects VM-specific hardware (e.g., VMware, VirtualBox, QEMU).                  |
| **Hypervisor Presence**     | ✔           | ✔               | ✔               | Checks for hypervisor flags in CPUID or system logs.                            |
| **CPU Timing Analysis**     | ✔           | ✔               | ✔               | Measures CPU instruction timing to detect virtualization anomalies.             |
| **Driver Signature Check**  | ✔           | ✔               | -               | Scans for virtualization-specific drivers (e.g., `vmmouse.sys`, `vboxguest`).   |
| **Process Analysis**        | ✔           | ✔               | ✔               | Detects known virtualization processes (e.g., `vmtoolsd`, `vboxservice`).       |
| **Memory Forensics**        | ✔           | ✔               | ✔               | Analyzes memory usage patterns and swap behavior for virtualization indicators.  |
| **Anti-Evasion Checks**     | ✔           | ✔               | ✔               | Detects hidden processes, core count discrepancies, and timing inconsistencies.  |
| **Filesystem Artifacts**    | ✔           | ✔               | ✔               | Scans for virtualization-specific files and directories.                        |
| **Network Analysis**        | ✔           | ✔               | ✔               | Checks for VM-specific MAC addresses and network configurations.                |
| **Uptime Analysis**         | ✔           | ✔               | ✔               | Detects suspiciously low system uptime (common in sandboxes).                   |

## Contributing 🤝

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📄

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgments 🏆

- Inspired by modern anti-malware research
- Uses [psutil](https://github.com/giampaolo/psutil) for system monitoring
- Leverages [py-cpuinfo](https://github.com/workhorsy/py-cpuinfo) for CPU analysis
