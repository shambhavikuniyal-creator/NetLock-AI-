import ctypes
import os

dll_path = os.path.abspath("hash_table.dll")
_c_lib = ctypes.CDLL(dll_path)

_c_lib.insert_ip.argtypes = [ctypes.c_char_p]
_c_lib.insert_ip.restype = None

_c_lib.check_ip.argtypes = [ctypes.c_char_p]
_c_lib.check_ip.restype = ctypes.c_int

_c_lib.clear_table.argtypes = []
_c_lib.clear_table.restype = None

def insert_blocked_ip(ip_address: str):
    _c_lib.insert_ip(ip_address.encode('utf-8'))

def is_ip_blocked(ip_address: str) -> bool:
    return _c_lib.check_ip(ip_address.encode('utf-8')) == 1

def clear_blocked_ips():
    _c_lib.clear_table()