import ctypes
import os

# 1. Locate and load the C Shared Library
dll_path = os.path.abspath("hash_table.dll")
c_engine = ctypes.CDLL(dll_path)

# 2. Define argument types and return types for C functions
c_engine.create_hash_table.restype = ctypes.c_void_p

c_engine.insert_ip.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
c_engine.insert_ip.restype = None

c_engine.is_ip_blocked.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
c_engine.is_ip_blocked.restype = ctypes.c_int


class FirewallEngine:

    def __init__(self):
        # Initialize the C Hash Table memory pointer
        self.table_ptr = c_engine.create_hash_table()
        print("⚡ [Python Bridge] C Hash Table initialized successfully!")

    def block_ip(self, ip_address: str, threat_score: int):
        """Passes an attacking IP string and score to C memory."""
        c_ip = ip_address.encode("utf-8")  # Convert Python string to C char*
        c_engine.insert_ip(self.table_ptr, c_ip, threat_score)

    def check_ip(self, ip_address: str) -> bool:
        """Performs O(1) fast C lookup for an incoming IP."""
        c_ip = ip_address.encode("utf-8")
        result = c_engine.is_ip_blocked(self.table_ptr, c_ip)
        return result == 1


# --- Quick Driver Test ---
if __name__ == "__main__":
    firewall = FirewallEngine()

    print("\n--- SIMULATING AI THREAT DETECTION & C BLOCKING ---")
    firewall.block_ip("192.168.1.50", 98)
    firewall.block_ip("10.0.0.99", 85)

    print("\n--- FAST O(1) C LOOKUPS FROM PYTHON ---")
    test_ips = ["192.168.1.50", "10.0.0.99", "172.16.0.5"]

    for ip in test_ips:
        status = " BLOCKED" if firewall.check_ip(ip) else " ALLOWED"
        print(f"Checking {ip}: {status}")