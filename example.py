from VirtualPyDetector import VirtualPyDetector

if __name__ == "__main__":
    VPD = VirtualPyDetector()
    if VPD.is_virtual_environment:
        print("virtualpy-detector: Detected")
    else:
        print("virtualpy-detector: Not Detected")
