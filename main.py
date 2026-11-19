import subprocess
import os
import sys
import time
import threading
import webbrowser

def compile_c_core():
    """Recompiles hash_table.c into hash_table.dll automatically on launch."""
    print("[INIT] Compiling C hash table engine into hash_table.dll...")
    try:
        # Runs GCC compilation directly
        result = subprocess.run(
            ["gcc", "-shared", "-o", "hash_table.dll", "hash_table.c"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("[SUCCESS] hash_table.dll compiled cleanly!")
        else:
            print(f"[WARNING] GCC output: {result.stderr}")
    except Exception as e:
        print(f"[ERROR] Could not execute GCC compilation: {e}")

def run_sniffer_in_background():
    """Runs the live sniffer daemon in a background thread."""
    print("[DAEMON] Starting NetLock AI live packet sniffer in background...")
    try:
        from live_sniffer import packet_callback
        from scapy.all import sniff
        # Sniff live network traffic
        sniff(filter="ip", prn=packet_callback, store=False)
    except Exception as e:
        print(f"[ERROR] Sniffer error (Ensure running as Admin for Npcap): {e}")

def open_browser():
    """Waits 1.5 seconds for Flask to initialize, then pops open the web browser."""
    time.sleep(1.5)
    print("[UI] Opening NetLock Security Dashboard in browser...")
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == "__main__":
    print("=" * 65)
    print("      NETLOCK AI - UNIFIED SINGLE-FILE SYSTEM LAUNCHER      ")
    print("=" * 65)
    
    # 1. Compile C core DLL automatically
    compile_c_core()
    
    # 2. Spawn live packet sniffer in background daemon thread
    sniffer_thread = threading.Thread(target=run_sniffer_in_background, daemon=True)
    sniffer_thread.start()
    
    # 3. Schedule automatic browser popup
    threading.Thread(target=open_browser, daemon=True).start()
    
    # 4. Launch Flask Web Dashboard on main thread
    from app import app
    print("[SERVER] Launching Flask Dashboard on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)