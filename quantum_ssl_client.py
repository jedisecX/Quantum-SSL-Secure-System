import socket import os import hashlib from Crypto.Cipher import AES from Crypto.Util.Padding import pad, unpad from pqcrypto.sign.falcon import verify import uuid import subprocess

def get_mac_address(): mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,8)]) return mac

def get_cpu_id(): try: if os.name == "nt": return subprocess.check_output("wmic cpu get processorid", shell=True).decode().split("\n")[1].strip() else: return subprocess.check_output("cat /proc/cpuinfo | grep 'serial'", shell=True).decode().split(": ")[-1].strip() except Exception as e: return "unknown"

def encrypt_message(message, key): cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16)) ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size)) return cipher.iv + ciphertext

def decrypt_message(ciphertext, key): iv, ciphertext = ciphertext[:16], ciphertext[16:] cipher = AES.new(key, AES.MODE_CBC, iv) return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def client(): client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) client_socket.connect(('localhost', 65432))

received_data = client_socket.recv(4096).split(b'|')
mac_address, cpu_id, qkd_key, falcon_public_key, signature = (
    received_data[0].decode(), received_data[1].decode(), received_data[2], received_data[3], received_data[4]
)

if mac_address == get_mac_address() and cpu_id == get_cpu_id() and verify((mac_address + cpu_id).encode(), signature, falcon_public_key):
    message = "Quantum SSL Secure Layer Active!"
    encrypted_data = encrypt_message(message, qkd_key)
    client_socket.send(encrypted_data)
    received_encrypted_data = client_socket.recv(4096)
    decrypted_message = decrypt_message(received_encrypted_data, qkd_key)
    print("Decrypted Message from Server:", decrypted_message)
else:
    print("Device authentication failed! Unauthorized client.")

del qkd_key
client_socket.close()

if name == "main": client()

