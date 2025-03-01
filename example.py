from VirtualPyDetector import VirtualPyDetector

if __name__ == "__main__":
    VPD = VirtualPyDetector()
    if VPD.venv_active:
        print("VirtualPyDetector: Detected")
    else:
        print("VirtualPyDetector: Not Detected")
