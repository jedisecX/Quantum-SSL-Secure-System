from qiskit import QuantumCircuit, Aer, transpile, assemble
import numpy as np
import hashlib

def quantum_rng(num_bits=16):
    backend = Aer.get_backend('qasm_simulator')
    circuit = QuantumCircuit(num_bits, num_bits)
    circuit.h(range(num_bits))  # Apply Hadamard gates to create superposition
    circuit.measure(range(num_bits), range(num_bits))
    
    transpiled_circuit = transpile(circuit, backend)
    qobj = assemble(transpiled_circuit)
    results = backend.run(qobj).result().get_counts()
    
    random_bits = list(results.keys())[0]  # Extract first result
    return int(random_bits, 2).to_bytes(num_bits // 8, 'big')

def bb84_qkd():
    backend = Aer.get_backend('qasm_simulator')
    num_bits = 16  # Key length
    
    alice_bits = np.random.randint(2, size=num_bits)  # Alice's raw bits
    alice_bases = np.random.randint(2, size=num_bits)  # Alice's basis choices
    bob_bases = np.random.randint(2, size=num_bits)  # Bob's basis choices
    
    circuit = QuantumCircuit(num_bits, num_bits)
    
    for i in range(num_bits):
        if alice_bits[i] == 1:
            circuit.x(i)
        if alice_bases[i] == 1:
            circuit.h(i)
        if bob_bases[i] == 1:
            circuit.h(i)
        circuit.measure(i, i)
    
    transpiled_circuit = transpile(circuit, backend)
    qobj = assemble(transpiled_circuit)
    results = backend.run(qobj).result().get_counts()
    
    bob_bits = np.array([int(k[::-1], 2) for k in results.keys()])
    matching_indices = alice_bases == bob_bases
    key_bits = bob_bits[matching_indices]  # Only keep matched measurements
    
    key = ''.join(map(str, key_bits))
    hashed_key = hashlib.sha256(key.encode()).digest()[:32]  # AES-256 key
    return hashed_key

if __name__ == "__main__":
    key = bb84_qkd()
    print("Generated Quantum Key:", key.hex())
