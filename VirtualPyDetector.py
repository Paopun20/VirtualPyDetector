import os
import re
import sys
import time
import ctypes
import platform
import subprocess
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from functools import partial
from typing import List, Set
import psutil

__VERSION__ = "0.0.1"

class VPDError(Exception):
    """Base class for exceptions in VirtualPyDetector."""
    def __init__(self, message):
        super().__init__(message)

class VirtualPyDetector:
    """
    Comprehensive detection system for virtual environments, sandboxes, and debuggers.
    Combines multiple detection techniques across different platforms with multiprocessing.
    """

    class VMChecks:
        """Virtual machine detection methods using hardware and system artifacts."""
        
        @staticmethod
        def check_vm_hardware() -> bool:
            """Detect VM through system hardware information."""
            system = platform.system()
            
            if system == "Windows":
                try:
                    output = subprocess.check_output(
                        ["wmic", "computersystem", "get", "model"],
                        encoding="utf-8",
                        timeout=3
                    )
                    vm_indicators = ("Virtual", "VMware", "VirtualBox", "Hyper-V", "QEMU")
                    return any(indicator in output for indicator in vm_indicators)
                except subprocess.CalledProcessError as e:
                    raise VPDError(f"Error checking VM hardware: {e}")
                except subprocess.TimeoutExpired:
                    return False

            elif system == "Darwin":  # macOS
                try:
                    output = subprocess.check_output(
                        ["sysctl", "hw.model"], 
                        encoding="utf-8", 
                        timeout=3
                    )
                    return any(vm in output for vm in ("VMware", "VirtualBox"))
                except subprocess.CalledProcessError as e:
                    raise VPDError(f"Error checking VM hardware: {e}")
                except subprocess.TimeoutExpired:
                    return False

            elif system == "Linux":
                try:
                    output = subprocess.check_output(
                        ["systemd-detect-virt"], 
                        encoding="utf-8", 
                        timeout=3
                    )
                    return output.strip() != "none"
                except subprocess.CalledProcessError as e:
                    raise VPDError(f"Error checking VM hardware: {e}")
                except subprocess.TimeoutExpired:
                    return False

            return False

        @staticmethod
        def check_mac_address() -> bool:
            """Check for virtualization-related MAC address prefixes."""
            try:
                command = "getmac" if platform.system() == "Windows" else "ifconfig"
                output = subprocess.check_output(
                    [command], 
                    encoding="utf-8", 
                    timeout=3
                )
                mac_pattern = r"(00:05:69|00:0C:29|00:50:56|00:1C:14|00:03:FF|00:05:00)"
                return re.search(mac_pattern, output) is not None
            except subprocess.CalledProcessError as e:
                raise VPDError(f"Error checking MAC address: {e}")
            except subprocess.TimeoutExpired:
                return False

        @staticmethod
        def check_vm_artifacts() -> bool:
            """Check for existence of known virtualization software artifacts."""
            vm_paths = [
                # macOS paths
                "/Applications/VMware Tools",
                "/Applications/VirtualBox.app",
                # Windows paths
                "C:\\Program Files\\VMware\\VMware Tools",
                "C:\\Program Files\\Oracle\\VirtualBox Guest Additions"
            ]
            return VirtualPyDetector.HelperFunctions.check_paths_exist(vm_paths)

        @staticmethod
        def check_virtualbox_drivers() -> bool:
            """Detect VirtualBox drivers on Windows systems."""
            if platform.system() != "Windows":
                return False

            drivers = [
                "VBoxGuest.sys",
                "VBoxMouse.sys",
                "VBoxSF.sys"
            ]
            driver_paths = [f"C:\\Windows\\System32\\drivers\\{driver}" for driver in drivers]
            return VirtualPyDetector.HelperFunctions.check_paths_exist(driver_paths)

        @staticmethod
        def check_cpu_features() -> bool:
            """Detect CPU features indicating virtualization environment."""
            if platform.system() == "Linux":
                try:
                    with open("/proc/cpuinfo", "r") as cpuinfo:
                        return any("hypervisor" in line for line in cpuinfo)
                except FileNotFoundError:
                    return False

            elif platform.system() == "Darwin":
                try:
                    output = subprocess.check_output(
                        ["sysctl", "machdep.cpu.features"],
                        encoding="utf-8",
                        timeout=3
                    )
                    return "VMM" in output  # Virtual Machine Monitor flag
                except subprocess.CalledProcessError as e:
                    raise VPDError(f"Error checking CPU features: {e}")
                except subprocess.TimeoutExpired:
                    return False
                
            return False

    class DebuggerChecks:
        """Debugger and sandbox detection methods."""
        
        @staticmethod
        def check_hypervisor() -> bool:
            """Detect hypervisor presence using platform-specific APIs."""
            if platform.system() == "Windows":
                try:
                    return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(29))
                except (AttributeError, OSError):
                    return False
                
            elif platform.system() == "Darwin":
                try:
                    output = subprocess.check_output(
                        ["sysctl", "kern.hv_support"], 
                        encoding="utf-8", 
                        timeout=3
                    )
                    return "1" in output
                except subprocess.CalledProcessError as e:
                    raise VPDError(f"Error checking hypervisor: {e}")
                except subprocess.TimeoutExpired:
                    return False
                
            return False

        @staticmethod
        def check_sandbox_files() -> bool:
            """Check for files/directories indicative of sandbox environments."""
            sandbox_paths = [
                "/Applications/WindowsSandbox.app",  # Hypothetical macOS path
                "C:\\Program Files\\WindowsApps\\Microsoft.WindowsSandbox_"
            ]
            return VirtualPyDetector.HelperFunctions.check_paths_exist(sandbox_paths)

        @staticmethod
        def detect_debugger() -> bool:
            """Detect debugger presence through platform-specific methods."""
            if platform.system() == "Windows":
                try:
                    return bool(ctypes.windll.kernel32.IsDebuggerPresent())
                except (AttributeError, OSError):
                    return False

            elif platform.system() in {"Darwin", "Linux"}:
                try:
                    parent_process = psutil.Process(os.getppid()).name().lower()
                    return parent_process in {"lldb", "gdb"}
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False

            return False

        @staticmethod
        def anti_timing_check(threshold: float = 0.5) -> bool:
            """
            Detect timing anomalies suggestive of virtualization/debugging.
            
            Args:
                threshold: Maximum expected execution time for empty loop (seconds)
            """
            start_time = time.perf_counter()
            for _ in range(1_000_000):
                pass  # Intentional no-op for timing measurement
            elapsed = time.perf_counter() - start_time
            return elapsed > threshold

    class ProcessChecks:
        """Detection of suspicious processes associated with analysis environments."""
        
        @staticmethod
        def detect_suspicious_processes() -> bool:
            """Threaded detection of known sandbox/VM-related processes."""
            suspicious_processes: Set[str] = {
                "vmtoolsd", "vboxservice", "wireshark",
                "fiddler", "sandboxie", "processhacker"
            }

            def process_check(proc: psutil.Process) -> bool:
                try:
                    return proc.info["name"].lower() in suspicious_processes
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return False

            with ThreadPoolExecutor() as executor:
                processes = psutil.process_iter(["name"])
                futures = [executor.submit(process_check, p) for p in processes]
                return any(f.result() for f in as_completed(futures))

    class HelperFunctions:
        """Utility methods supporting detection functionality."""
        
        @staticmethod
        def check_paths_exist(paths: List[str]) -> bool:
            """Check if any of the specified paths exist on the filesystem."""
            return any(os.path.exists(path) for path in paths)

    @property
    def venv_active(self) -> bool:
        """
        Aggregate all detection checks into a single property using multiprocessing.
        
        Returns:
            bool: True if any virtualization/debugging indicators are found
        """
        check_functions = [
            self.VMChecks.check_vm_hardware,
            self.VMChecks.check_mac_address,
            self.VMChecks.check_vm_artifacts,
            self.VMChecks.check_virtualbox_drivers,
            self.VMChecks.check_cpu_features,
            self.DebuggerChecks.check_hypervisor,
            self.DebuggerChecks.check_sandbox_files,
            self.DebuggerChecks.detect_debugger,
            partial(self.DebuggerChecks.anti_timing_check, threshold=0.5),
            self.ProcessChecks.detect_suspicious_processes,
        ]

        try:
            with ProcessPoolExecutor() as executor:
                futures = [executor.submit(func) for func in check_functions]
                results = []
                for future in as_completed(futures):
                    results.append(future.result())
                    if future.result():  # Early exit if any check is True
                        executor.shutdown(wait=False, cancel_futures=True)
                        return True
        except Exception as e:
            raise VPDError(f"Error during multiprocessed checks: {e}")

        return any(results)

    @property
    def is_virtualized(self) -> bool:
        """
        Check if the environment is virtualized.

        Returns:
            bool: True if a virtualized environment is detected, False otherwise.
        """
        virtualization_checks = [
            self.VMChecks.check_vm_hardware(),
            self.VMChecks.check_mac_address(),
            self.VMChecks.check_vm_artifacts(),
            self.VMChecks.check_virtualbox_drivers(),
            self.VMChecks.check_cpu_features(),
        ]
        return any(virtualization_checks)

    @property
    def is_debugged(self) -> bool:
        """
        Check if a debugger is attached to the process.

        Returns:
            bool: True if a debugger is detected, False otherwise.
        """
        debugger_checks = [
            self.DebuggerChecks.check_hypervisor(),
            self.DebuggerChecks.detect_debugger(),
            self.DebuggerChecks.anti_timing_check(),
        ]
        return any(debugger_checks)

    @property
    def is_sandboxed(self) -> bool:
        """
        Check if the environment is a sandbox.

        Returns:
            bool: True if a sandbox environment is detected, False otherwise.
        """
        sandbox_checks = [
            self.DebuggerChecks.check_sandbox_files(),
            self.ProcessChecks.detect_suspicious_processes(),
        ]
        return any(sandbox_checks)
    
    @property
    def is_analyzed(self) -> bool:
        """
        Check if the environment is under analysis.

        Returns:
            bool: True if an analysis environment is detected, False otherwise.
        """
        analysis_checks = [
            self.is_virtualized,
            self.is_debugged,
            self.is_sandboxed,
        ]
        return any(analysis_checks)
    
    @property
    def is_safe(self) -> bool:
        """
        Check if the environment is safe.

        Returns:
            bool: True if no analysis environment is detected, False otherwise.
        """
        return not self.is_analyzed
    
    @property
    def is_unsafe(self) -> bool:
        """
        Check if the environment is unsafe.

        Returns:
            bool: True if an analysis environment is detected, False otherwise.
        """
        return self.is_analyzed
    
    @property
    def is_virtual(self) -> bool:
        """
        Check if the environment is virtual.

        Returns:
            bool: True if a virtual environment is detected, False otherwise.
        """
        return self.is_virtualized
    
    @property
    def is_debug(self) -> bool:
        """
        Check if a debugger is attached to the process.

        Returns:
            bool: True if a debugger is detected, False otherwise.
        """
        return self.is_debugged
    
    @property
    def is_sandbox(self) -> bool:
        """
        Check if the environment is a sandbox.

        Returns:
            bool: True if a sandbox environment is detected, False otherwise.
        """
        return self.is_sandboxed
    
    @property
    def is_analysis(self) -> bool:
        """
        Check if the environment is under analysis.

        Returns:
            bool: True if an analysis environment is detected, False otherwise.
        """
        return self.is_analyzed
    
    @property
    def get_all_checks(self) -> dict:
        """
        Get all checks.

        Returns:
            dict: All checks.
        """
        return {
            "is_virtualized": self.is_virtualized,
            "is_debugged": self.is_debugged,
            "is_sandboxed": self.is_sandboxed,
            "is_analyzed": self.is_analyzed,
            "is_safe": self.is_safe,
            "is_unsafe": self.is_unsafe,
            "is_virtual": self.is_virtual,
            "is_debug": self.is_debug,
            "is_sandbox": self.is_sandbox,
            "is_analysis": self.is_analysis,
            "venv_active": self.venv_active,
        }