import json
import random

# Leer el archivo JSON
with open('./parameters.json') as file:
    data = json.load(file)

# Función para generar una clave pública y compartida usando Diffie-Hellman
def diffie_hellman_with_params(p, g):
    # Elegimos valores privados aleatorios para ambas partes
    private_key_1 = random.randint(1, p-1)
    private_key_2 = random.randint(1, p-1)

    # Claves públicas (A = g^a mod p y B = g^b mod p)
    public_key_1 = pow(g, private_key_1, p)  # g^a mod p
    public_key_2 = pow(g, private_key_2, p)  # g^b mod p

    # Claves compartidas (K = B^a mod p y K = A^b mod p, ambas deben ser iguales)
    shared_key_1 = pow(public_key_2, private_key_1, p)  # B^a mod p
    shared_key_2 = pow(public_key_1, private_key_2, p)  # A^b mod p

    return public_key_1, public_key_2, shared_key_1, shared_key_2

# Iterar sobre los parámetros y ejecutar Diffie-Hellman
for param in data["parameters"]:
    p = param["p"]
    g = param["g"]
    print(f"Ejecutando Diffie-Hellman con p={p}, g={g}")
    
    # Ejecutar el intercambio de llaves
    d1_pubkey, d2_pubkey, D1_SHAREDKEY, D2_SHAREDKEY = diffie_hellman_with_params(p, g)
    
    # Imprimir resultados
    print(f"Public Key 1: {d1_pubkey}")
    print(f"Public Key 2: {d2_pubkey}")
    print(f"Shared Key 1: {D1_SHAREDKEY}")
    print(f"Shared Key 2: {D2_SHAREDKEY}")
    assert D1_SHAREDKEY == D2_SHAREDKEY, "Error: Las claves compartidas no coinciden"
    print("Las claves compartidas coinciden!\n")
