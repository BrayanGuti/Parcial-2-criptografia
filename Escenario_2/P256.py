from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 1. Generar la clave privada para cada participante usando la curva P-256
def generar_clave_privada():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

# 2. Obtener la clave pública a partir de la clave privada
def obtener_clave_publica(clave_privada):
    return clave_privada.public_key()

# 3. Intercambio de claves y cálculo del secreto compartido
def calcular_secreto_compartido(clave_privada, clave_publica_otro):
    # Genera el secreto compartido usando la clave pública del otro participante
    secreto_compartido = clave_privada.exchange(ec.ECDH(), clave_publica_otro)
    return secreto_compartido

# 4. Serializar la clave pública para intercambio
def serializar_clave_publica(clave_publica):
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# 5. Deserializar la clave pública recibida
def deserializar_clave_publica(clave_publica_bytes):
    return serialization.load_pem_public_key(clave_publica_bytes, backend=default_backend())

# Ejemplo de uso
if __name__ == "__main__":
    # Usuario A
    clave_privada_A = generar_clave_privada()
    clave_publica_A = obtener_clave_publica(clave_privada_A)

    # Usuario B
    clave_privada_B = generar_clave_privada()
    clave_publica_B = obtener_clave_publica(clave_privada_B)

    # Serializar las claves públicas para intercambiarlas (en un caso real se envían por la red)
    clave_publica_A_serializada = serializar_clave_publica(clave_publica_A)
    clave_publica_B_serializada = serializar_clave_publica(clave_publica_B)

    # Deserializar las claves públicas en el lado receptor
    clave_publica_A_recibida = deserializar_clave_publica(clave_publica_A_serializada)
    clave_publica_B_recibida = deserializar_clave_publica(clave_publica_B_serializada)

    # Cada usuario calcula el secreto compartido usando su clave privada y la clave pública del otro
    secreto_A = calcular_secreto_compartido(clave_privada_A, clave_publica_B_recibida)
    secreto_B = calcular_secreto_compartido(clave_privada_B, clave_publica_A_recibida)

    # El secreto debe ser igual para ambos usuarios
    print(f"Secreto compartido A: {secreto_A.hex()}")
    print(f"Secreto compartido B: {secreto_B.hex()}")

    assert secreto_A == secreto_B, "El secreto compartido no coincide"
