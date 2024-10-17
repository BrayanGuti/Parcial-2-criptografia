import socket
import threading
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

def handle_client(conn):
    # Fase 1: Intercambio de claves
    clave_privada_server = generar_clave_privada()
    clave_publica_server = obtener_clave_publica(clave_privada_server)
    clave_publica_server_serializada = serializar_clave_publica(clave_publica_server)

    clave_publica_Client_serializada = conn.recv(1024)
    conn.send(clave_publica_server_serializada)

    clave_publica_client = deserializar_clave_publica(clave_publica_Client_serializada)
    clave_compartida = calcular_secreto_compartido(clave_privada_server, clave_publica_client)
    clave_simetrica = generate_symmetric_key(clave_compartida)
    print(f"Clave simétrica generada en el servidor: {clave_simetrica.hex()}")

    # Fase 2: Comunicación cifrada
    while True:
        # Recibir y descifrar mensaje del cliente
        encrypted_message = conn.recv(1024)
        message = decrypt_message(clave_simetrica, encrypted_message)
        print(f"Cliente: {message}")
        if message.lower() == 'exit':
            break

        # Enviar respuesta cifrada al cliente
        response = input("Tú: ")
        encrypted_response = encrypt_message(clave_simetrica, response)
        conn.send(encrypted_response)

    conn.close()

def server_program():
    host = '127.0.0.1'
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    print(f"Servidor escuchando en {host}:{port}")

    while True:
        conn, address = server_socket.accept()
        print(f"Conexión desde: {str(address)}")
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()

if __name__ == '__main__':
    server_program()
