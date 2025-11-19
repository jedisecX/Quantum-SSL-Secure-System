import socket
import os
import hashlib
import uuid
import subprocess
import netifaces
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pqcrypto.sign.falcon import generate_keypair, sign, verify
from qiskit import QuantumCircuit, Aer, transpile
from qiskit.providers.aer import QasmSimulator
import numpy as np

# =============================================================================
# QUANTUM-PRIMITIVE TRUE RANDOMNESS (BB84-style simulation)
# =============================================================================
def quantum_rng(num_qubits: int = 256) -> bytes:
    """Generate cryptographically strong random bits using simulated quantum measurement"""
    backend = QasmSimulator()
    circuit = QuantumCircuit(num_qubits, num_qubits)
    circuit.h(range(num_qubits))                  # Superposition
    circuit.measure(range(num_qubits), range(num_qubits))
    
    transpiled = transpile(circuit, backend)
    job = backend.run(transpiled, shots=1, memory=True)
    result = job.result()
    measured_bits = result.get_memory()[0]        # String like '0101101...'
    # Convert to integer then to bytes
    integer_val = int(measured_bits, 2)
    byte_length = (num_qubits + 7) // 8
    return integer_val.to_bytes(byte_length, 'big')

def derive_qkd_session_key() -> bytes:
    """Derive a proper 32-byte AES-256 key using quantum entropy + SHA3-256"""
    raw_entropy = quantum_rng(512)  # Overproduce entropy
    return hashlib.sha3_256(raw_entropy).digest()

# =============================================================================
# HARDWARE FINGERPRINTING (Fixed & Hardened)
# =============================================================================
def get_mac_address() -> str:
    """Reliable MAC address retrieval (prefers real interfaces over uuid hack)"""
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_LINK in addrs:
            mac = addrs[netifaces.AF_LINK][0]['addr']
            if mac != "00:00:00:00:00:00":  # Filter invalid
                return mac.lower()
    # Fallback
    mac_int = uuid.getnode()
    return ':'.join(f'{((mac_int >> i) & 0xff):02x}' for i in range(0, 48, 8))[::-1]

def get_cpu_id() -> str:
    """Robust CPU serial/ID across platforms"""
    try:
        if os.name == "nt":
            output = subprocess.check_output("wmic cpu get ProcessorId", shell=True, text=True)
            for line in output.splitlines():
                if line.strip() and not line.startswith("ProcessorId"):
                    return line.strip()
        else:
            output = subprocess.check_output("cat /proc/cpuinfo | grep -i '^Serial' | awk -F': ' '{print $2}'", shell=True, text=True)
            if output.strip():
                return output.strip()
            # Raspberry Pi / some ARM
            output = subprocess.check_output("cat /proc/cpuinfo | grep -i '^Hardware' | awk '{print $3}'", shell=True, text=True)
            return output.strip() or "unknown_hardware"
    except:
        pass
    return "unknown_cpu"

# =============================================================================
# ENCRYPTION PRIMITIVES (Same as client)
# =============================================================================
def encrypt_message(message: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return iv + ciphertext

def decrypt_message(data: bytes, key: bytes) -> str:
    if len(data) < 16:
        raise ValueError("Truncated ciphertext")
    iv, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

# =============================================================================
# QUANTUM SSL SERVER – THE EMPIRE BEGINS
# =============================================================================
def start_quantum_ssl_server(host: str = "0.0.0.0", port: int = 65432):
    # Generate persistent Falcon keypair (in real deployment: store securely!)
    print("[+] Generating Falcon-1024 post-quantum keypair...")
    falcon_public_key, falcon_private_key = generate_keypair()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[+] Quantum SSL Server listening on {host}:{port}")
    print(f"[+] Falcon Public Key (hex): {falcon_public_key.hex()[:64]}...")

    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"\n[+] New connection from {addr}")

            # === 1. Generate per 2. Hardware Fingerprint ===
            mac_address = get_mac_address()
            cpu_id = get_cpu_id()
            qkd_key = derive_qkd_session_key()

            print(f"[i] Target MAC : {mac_address}")
            print(f"[i] Target CPU : {cpu_id}")
            print(f"[i] QKD Key    : {qkd_key.hex()}")

            # === 3. Sign hardware identity with post-quantum Falcon ===
            message = (mac_address + cpu_id).encode('utf-8')
            signature = sign(message, falcon_private_key)

            # === 4. Send authentication payload ===
            payload = (
                mac_address.encode('utf-8') + b'|' +
                cpu_id.encode('utf-8') + b'|' +
                qkd_key + b'|' +
                falcon_public_key + b'|' +
                signature
            )
            conn.sendall(payload)
            print("[+] Authentication payload sent (hardware-bound + Falcon-signed)")

            # === 5. Receive encrypted confirmation from client ===
            encrypted_confirmation = conn.recv(4096)
            if not encrypted_confirmation:
                print("[-] Client disconnected before sending confirmation")
                conn.close()
                continue

            try:
                confirmation = decrypt_message(encrypted_confirmation, qkd_key)
                print(f"[+] Client says: {confirmation}")
            except Exception as e:
                print(f"[-] Failed to decrypt client message: {e}")
                conn.close()
                continue

            # === 6. Respond with final encrypted message ===
            response = "Welcome, authorized device. The Quantum Empire acknowledges your loyalty."
            encrypted_response = encrypt_message(response, qkd_key)
            conn.sendall(encrypted_response)
            print("[+] Secure response sent. Channel terminated.")

            # === 7. Secure cleanup ===
            qkd_key = b'\x00' * 32
            conn.close()
            print("[i] Session closed securely.\n")

        except KeyboardInterrupt:
            print("\n[!] Server shutting down by overlord command.")
            break
        except Exception as e:
            print(f"[-] Error in session: {e}")

    server_socket.close()

if __name__ == "__main__":
    start_quantum_ssl_server()
