import socket
import os
import hashlib
import uuid
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pqcrypto.sign.falcon import verify  # Make sure you have libpqcrypto installed correctly

def get_mac_address():
    """Get MAC address as colon-separated hex string using uuid.getnode()"""
    mac_int = uuid.getnode()
    if (mac_int >> 40) & 0xFFFF == 0x0000:  # Handle locally administered MACs properly
        return ':'.join(['{:02x}'.format((mac_int >> i) & 0xff) for i in range(0, 48, 8)][::-1])
    return ':'.join(['{:02x}'.format((mac_int >> i) & 0xff) for i in range(0, 48, 8)][::-1])

def get_cpu_id():
    """Platform-independent CPU serial/ID retrieval"""
    try:
        if os.name == "nt":  # Windows
            output = subprocess.check_output("wmic cpu get ProcessorId", shell=True, text=True)
            lines = [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("ProcessorId")]
            return lines[0] if lines else "unknown"
        else:  # Linux (common on servers/embedded)
            output = subprocess.check_output("cat /proc/cpuinfo | grep Serial | awk -F': ' '{print $2}'", shell=True, text=True)
            return output.strip() or "unknown"
    except Exception:
        return "unknown"

def encrypt_message(message: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return iv + ciphertext

def decrypt_message(encrypted_data: bytes, key: bytes) -> str:
    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data: too short")
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('127.0.0.1', 65432))  # Use 127.0.0.1 instead of localhost for reliability
        print("[+] Connected to Quantum SSL Server")

        # Receive initial authentication payload
        data = client_socket.recv(4096)
        if not data:
            print("[-] No data received from server.")
            return

        try:
            parts = data.split(b'|', 4)  # Only split into 5 parts max
            if len(parts) != 5:
                raise ValueError("Invalid number of fields from server")

            received_mac = parts[0].decode('utf-8')
            received_cpu = parts[1].decode('utf-8')
            qkd_key = parts[2]                    # Raw 32-byte key (AES-256)
            falcon_public_key = parts[3]          # Raw public key bytes
            signature = parts[4]                  # Falcon signature over (mac + cpu)

        except Exception as e:
            print(f"[-] Failed to parse server message: {e}")
            return

        local_mac = get_mac_address()
        local_cpu = get_cpu_id()

        print(f"[i] Local MAC : {local_mac}")
        print(f"[i] Local CPU : {local_cpu}")
        print(f"[i] Server MAC: {received_mac}")
        print(f"[i] Server CPU: {received_cpu}")

        # === CRITICAL: Verify hardware binding + post-quantum signature ===
        message_to_verify = (received_mac + received_cpu).encode('utf-8')

        try:
            is_valid_signature = verify(message_to_verify, signature, falcon_public_key)
        except Exception as e:
            print(f"[-] Falcon signature verification failed: {e}")
            is_valid_signature = False

        if (received_mac == local_mac and
            received_cpu == local_cpu and
            len(qkd_key) == 32 and
            is_valid_signature):
            
            print("[+] Device authentication successful! Quantum-secure channel established.")

            # Send encrypted confirmation
            confirmation = "Quantum SSL Secure Layer Active! Client Authenticated."
            encrypted_response = encrypt_message(confirmation, qkd_key)
            client_socket.sendall(encrypted_response)

            # Receive server reply
            encrypted_reply = client_socket.recv(4096)
            if encrypted_reply:
                try:
                    reply = decrypt_message(encrypted_reply, qkd_key)
                    print("[+] Decrypted Message from Server:", reply)
                except Exception as e:
                    print("[-] Failed to decrypt server response:", e)
            else:
                print("[-] No response from server.")

        else:
            print("[-] Device authentication failed! Unauthorized client.")
            if received_mac != local_mac:
                print("    → MAC address mismatch")
            if received_cpu != local_cpu:
                print("    → CPU ID mismatch")
            if not is_valid_signature:
                print("    → Invalid Falcon signature")

    except ConnectionRefusedError:
        print("[-] Connection refused. Is the Quantum SSL server running on port 65432?")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        client_socket.close()
        # Securely zero the QKD key
        if 'qkd_key' in locals():
            qkd_key = b'\x00' * len(qkd_key)  # Overwrite in memory
        print("[i] Connection closed.")

if __name == "__main__":
    client()
