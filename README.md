# Quantum SSL Secure Communication System
A Quantum Secure Communication System with QKD and Falcon-1024 authentication.

![1000003022](https://github.com/user-attachments/assets/c7952a2f-093c-4cee-b100-daca1154d7cf)


## Features:
- Quantum Key Distribution (QKD)
- AES-256 Encryption
- Falcon-1024 Authentication
- VPN & TLS 1.3 Support


Running the System

Start the Server: python quantum_ssl_server.py

Start the Client: python quantum_ssl_client.py

Quantum SSL Secure Communication System

A Quantum Key Distribution (QKD) and Falcon-1024 authenticated secure communication system. This system ensures highly secure, encrypted, and anonymous communication using quantum-resistant cryptography.

Features

Quantum Key Distribution (BB84 Protocol)

AES-256 Encryption for Secure Messaging

Falcon-1024 Digital Signatures for Authentication

MAC Address & CPU ID-Based Device Verification

TLS 1.3 & VPN Support for Secure Transport

Rotating Keys & Auto-Destroy Session Data


Installation & Setup

System Requirements

Python 3.8+

Qiskit (Quantum Key Distribution Simulation)

pqcrypto (Falcon-1024 Signatures)

pycryptodome (AES-256 Encryption)

netifaces (Network Interface Management)

OpenSSL (TLS 1.3 for Secure Transport)


1. Clone the Repository

git clone https://github.com/YOUR_USERNAME/Quantum-SSL-Secure-System.git
cd Quantum-SSL-Secure-System

2. Install Dependencies

## Installation
```
pip install qiskit pqcrypto pycryptodome netifaces
```

3. Running the Secure Server

python quantum_ssl_server.py

Starts the QKD key exchange and Falcon-1024 authentication.

Binds to a secure TLS 1.3 socket awaiting client connections.


4. Running the Secure Client

python quantum_ssl_client.py

Authenticates using MAC and CPU ID.

Generates a unique Falcon key per device.

Establishes a secure QKD session with AES-256 encryption.


GitHub Pages Website

View project details: GitHub Pages

License

This project is licensed under the MIT License.
