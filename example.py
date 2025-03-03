from VirtualPyDetector import VirtualPyDetector

if __name__ == "__main__":
    # Create an instance of the VirtualPyDetector class.
    VPD = VirtualPyDetector()

    # Check if any virtualization or debugging indicators are active.
    if VPD.venv_active:
        print("VirtualPyDetector: Detected")
    else:
        print("VirtualPyDetector: Not Detected")

    # Check if the environment is virtualized.
    if VPD.is_virtualized:
        print("VirtualPyDetector: Virtualized")
    else:
        print("VirtualPyDetector: Not Virtualized")

    # Check if a debugger is attached.
    if VPD.is_debugged:
        print("VirtualPyDetector: Debugged")
    else:
        print("VirtualPyDetector: Not Debugged")

    # Check if the environment is a sandbox.
    if VPD.is_sandboxed:
        print("VirtualPyDetector: Sandboxed")
    else:
        print("VirtualPyDetector: Not Sandboxed")

    # Check if the environment is under analysis (virtualized, debugged, or sandboxed).
    if VPD.is_analyzed:
        print("VirtualPyDetector: Analyzed")
    else:
        print("VirtualPyDetector: Not Analyzed")

    # Check if the environment is considered safe (not under analysis).
    if VPD.is_safe:
        print("VirtualPyDetector: Safe")
    else:
        print("VirtualPyDetector: Not Safe")

    # Check if the environment is considered unsafe (under analysis).
    if VPD.is_unsafe:
        print("VirtualPyDetector: Unsafe")
    else:
        print("VirtualPyDetector: Not Unsafe")

    # Check if the environment is virtual. (Alias for is_virtualized)
    if VPD.is_virtual:
        print("VirtualPyDetector: Virtual")
    else:
        print("VirtualPyDetector: Not Virtual")

    # Check if a debugger is attached. (Alias for is_debugged)
    if VPD.is_debug:
        print("VirtualPyDetector: Debug")
    else:
        print("VirtualPyDetector: Not Debug")

    # Check if the environment is a sandbox. (Alias for is_sandboxed)
    if VPD.is_sandbox:
        print("VirtualPyDetector: Sandbox")
    else:
        print("VirtualPyDetector: Not Sandbox")

    # Check if the environment is under analysis. (Alias for is_analyzed)
    if VPD.is_analysis:
        print("VirtualPyDetector: Analysis")
    else:
        print("VirtualPyDetector: Not Analysis")

    # Print a dictionary containing the results of all checks.
    print("VirtualPyDetector All Checks: " + str(VPD.get_all_checks))
