import os
import re
import sys
import time
import ctypes
import struct
import platform
import subprocess
from typing import Generator, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import cpuinfo
import psutil

# Constants
VM_MAC_PREFIXES = re.compile(
    r"(^00:05:69$|"      # VMware
    r"^00:0C:29$|"       # VMware
    r"^00:1C:14$|"       # VMware
    r"^00:50:56$|"       # VMware
    r"^08:00:27$|"       # VirtualBox
    r"^0A:00:27$|"       # VirtualBox
    r"^00:16:3E$|"       # Xen/KVM
    r"^00:03:(FF|1A)$|"  # QEMU
    r"^00:15:5D$)"       # Hyper-V
)

VIRTUAL_DEVICES = {
    "/dev/vmci", "/dev/vmmon", "/dev/vmxnet",  # VMware
    "/dev/vboxguest", "/dev/vboxuser",         # VirtualBox
    "/proc/xen", "/sys/bus/xen",               # Xen
    "/proc/vz",                                # OpenVZ
    "/proc/self/status:\nctx"                  # LXC
}

SUSPICIOUS_PROCESSES = {
    "vmtoolsd", "vmware-user", "vboxservice",
    "qemu-ga", "prl_cc", "xenstored", "hv_kvp_daemon",
    "sandbox", "sbiedll", "SbieSvc", "SbieCtrl",
    "procmon", "wireshark", "fiddler", "ollydbg"
}

VM_ARTIFACTS = [
    # Windows
    r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
    r"C:\Windows\System32\drivers\vmmouse.sys",
    r"C:\Windows\System32\drivers\vmhgfs.sys",
    # Linux/Mac
    "/usr/lib/vmware-tools",
    "/usr/bin/VBoxClient",
    "/Library/Application Support/VMware Tools",
    # Cross-platform
    "/etc/init.d/vmware-tools",
    "/usr/libexec/open-vm-tools",
    "/proc/driver/vmci"
]


class VirtualPyDetector:
    """
    Advanced virtualization and sandbox detection system.
    Combines hardware, software, and behavioral analysis.
    """

    class SystemInspector:
        """Hardware and firmware-level detection methods."""

        @staticmethod
        def check_virtual_hardware() -> bool:
            """Detect VM-specific hardware signatures."""
            try:
                system = platform.system()

                if system == "Windows":
                    result = subprocess.run(
                        ["wmic", "baseboard", "get", "product"],
                        capture_output=True, text=True, timeout=1.5,
                        check=True, creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    return any(x in result.stdout for x in {
                        "Virtual", "VMware", "VirtualBox", "QEMU"
                    })

                if system == "Darwin":
                    result = subprocess.run(
                        ["system_profiler", "SPHardwareDataType"],
                        capture_output=True, text=True, timeout=2,
                        check=True
                    )
                    return "Model Identifier: VMware" in result.stdout

                if system == "Linux":
                    return any(os.path.exists(dev) for dev in VIRTUAL_DEVICES)

            except (subprocess.SubprocessError, PermissionError):
                pass
            return False

        @staticmethod
        def check_hypervisor_presence() -> bool:
            """Detect hypervisor presence using CPUID instruction."""
            try:
                if platform.system() == "Windows":
                    info = cpuinfo.get_cpu_info()
                    return "hypervisor" in info.get("flags", [])

                if platform.system() == "Linux":
                    with open("/proc/cpuinfo", "r") as f:
                        return "hypervisor" in f.read()

                if platform.system() == "Darwin":
                    result = subprocess.run(
                        ["sysctl", "-n", "machdep.cpu.features"],
                        capture_output=True, text=True, timeout=1,
                        check=True
                    )
                    return "VMM" in result.stdout

            except (OSError, subprocess.SubprocessError):
                return False

    class RuntimeAnalyzer:
        """Runtime environment analysis methods."""

        @staticmethod
        def check_cpu_timing_anomalies() -> bool:
            """Detect CPU timing anomalies using RDTSC instruction."""
            try:
                def rdtsc():
                    if platform.system() == "Windows":
                        return ctypes.windll.kernel32.__rdtsc()
                    else:
                        return struct.unpack("Q", struct.pack("LL", *ctypes.c_uint64()))[0]

                start = rdtsc()
                time.sleep(0.001)  # 1ms sleep
                end = rdtsc()
                cycles = end - start

                # Normal systems: ~1M cycles for 1ms
                return cycles < 500_000 or cycles > 2_000_000

            except:
                return False

        @staticmethod
        def check_memory_artifacts() -> bool:
            """Detect memory anomalies (e.g., low RAM, unusual pagefile)."""
            try:
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()

                # Check for unusually low RAM or high swap usage
                return (mem.total < 2 * 1024**3 or  # <2GB RAM
                        swap.used > mem.total * 0.5)  # >50% swap used
            except:
                return False

    class ForensicAnalyzer:
        """System forensic analysis methods."""

        @staticmethod
        def check_filesystem_artifacts() -> bool:
            """Check for known virtualization tool artifacts."""
            return any(os.path.exists(path) for path in VM_ARTIFACTS)

        @staticmethod
        def check_driver_signatures() -> bool:
            """Analyze loaded drivers for virtualization signatures."""
            try:
                if platform.system() == "Windows":
                    drivers = subprocess.check_output(
                        ["driverquery", "/V"],
                        text=True, timeout=2
                    )
                    return any(x in drivers for x in {"vmw", "vbox", "qemu"})

                if platform.system() == "Linux":
                    return os.path.exists("/proc/modules") and any(
                        line.startswith(("vbox", "vmw", "xen"))
                        for line in open("/proc/modules")
                    )

            except (subprocess.SubprocessError, FileNotFoundError):
                return False
            return False

    class BehavioralAnalysis:
        """Behavioral analysis detection methods."""

        @staticmethod
        def timing_analysis() -> bool:
            """Detect timing anomalies in execution."""
            def _stress_test():
                start = time.perf_counter_ns()
                [i for i in range(10**6)]  # Memory stress
                return time.perf_counter_ns() - start

            # Run multiple tests
            tests = [_stress_test() for _ in range(3)]
            avg_time = sum(tests) / len(tests)

            # Normal systems should complete < 50ms (adjust based on hardware)
            return avg_time > 100_000_000  # 100ms threshold

        @staticmethod
        def check_system_uptime() -> bool:
            """Check for suspiciously low uptime."""
            try:
                return psutil.boot_time() > (time.time() - 300)  # <5m uptime
            except:
                return False

    class AntiEvasion:
        """Anti-evasion techniques to detect hidden virtualization."""

        @staticmethod
        def check_hidden_processes() -> bool:
            """Detect discrepancies in process listing."""
            try:
                proc_count1 = len(list(psutil.process_iter()))
                proc_count2 = len(os.listdir("/proc")) if platform.system() == "Linux" else proc_count1
                return abs(proc_count1 - proc_count2) > 10
            except:
                return False

        @staticmethod
        def check_cpu_core_discrepancy() -> bool:
            """Detect discrepancies in CPU core count."""
            try:
                logical_cores = psutil.cpu_count(logical=True)
                physical_cores = psutil.cpu_count(logical=False)
                return logical_cores != physical_cores * 2  # Hyper-threading check
            except:
                return False

    def __detection_pipeline(self) -> Generator[bool, None, None]:
        """Optimized detection pipeline with short-circuiting."""
        # Stage 1: Quick hardware checks
        yield self.SystemInspector.check_virtual_hardware()
        yield self.SystemInspector.check_hypervisor_presence()

        # Stage 2: System configuration analysis
        yield self.RuntimeAnalyzer.check_cpu_timing_anomalies()
        yield self.ForensicAnalyzer.check_filesystem_artifacts()

        # Stage 3: Process and driver analysis
        yield self.ForensicAnalyzer.check_driver_signatures()

        # Stage 4: Behavioral analysis
        yield self.BehavioralAnalysis.timing_analysis()
        yield self.BehavioralAnalysis.check_system_uptime()

        # Stage 5: Anti-evasion checks
        yield self.AntiEvasion.check_hidden_processes()
        yield self.AntiEvasion.check_cpu_core_discrepancy()
        
    @property
    def is_virtual_environment(self) -> bool:
        # for result in self.__detection_pipeline():
        #     print(result)
        return any(self.__detection_pipeline())