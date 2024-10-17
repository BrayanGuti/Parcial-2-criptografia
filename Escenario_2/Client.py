import socket
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from P256 import generar_clave_privada, obtener_clave_publica, calcular_secreto_compartido, serializar_clave_publica, deserializar_clave_publica

# Función para generar la clave simétrica a partir de la clave compartida
def generate_symmetric_key(shared_key):
    shared_key_bytes = str(shared_key).encode()
    return hashlib.sha256(shared_key_bytes).digest()

# Función para cifrar un mensaje usando AES-256-CBC
def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Generar un IV aleatorio
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext  # Devuelve el IV concatenado con el ciphertext

# Función para descifrar un mensaje usando AES-256-CBC
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]  # El IV está en los primeros 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode()

def client_program():
    host = '127.0.0.1'
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Fase 1: Intercambio de claves
    clave_privada_Client = generar_clave_privada()
    clave_publica_Client = obtener_clave_publica(clave_privada_Client)
    clave_publica_Client_serializada = serializar_clave_publica(clave_publica_Client)

    client_socket.send(clave_publica_Client_serializada)
    clave_publica_servidor_serializada = client_socket.recv(1024)
    clave_publica_servidor = deserializar_clave_publica(clave_publica_servidor_serializada)

    clave_compartida = calcular_secreto_compartido(clave_privada_Client, clave_publica_servidor)
    clave_simetrica = generate_symmetric_key(clave_compartida)
    print(f"Clave simétrica generada en el cliente: {clave_simetrica.hex()}")

    # Fase 2: Comunicación cifrada
    while True:
        message = input("Tú: ")
        if message.lower() == 'exit':
            break
        encrypted_message = encrypt_message(clave_simetrica, message)
        client_socket.send(encrypted_message)

        # Recibir y descifrar respuesta del servidor
        encrypted_response = client_socket.recv(1024)
        response = decrypt_message(clave_simetrica, encrypted_response)
        print(f"Servidor: {response}")

    client_socket.close()

if __name__ == '__main__':
    client_program()
