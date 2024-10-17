import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def handle_client(conn, private_key):
    print("Cliente conectado.")
    
    # Enviar clave pública al cliente
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(pem)
    
    while True:
        # Recibir mensaje cifrado del cliente
        ciphertext = conn.recv(1024)
        if not ciphertext:
            break
        
        # Descifrar mensaje
        message = decrypt(private_key, ciphertext).decode()
        if message.lower() == 'exit':
            break
        
        print(f"Cliente: {message}")
        
        # Enviar respuesta al cliente
        response = input("Tú: ")
        response_ciphertext = encrypt(public_key, response.encode())
        conn.send(response_ciphertext)

    conn.close()  # Cerrar la conexión con el cliente
    print("Cliente desconectado.")

def server_program():
    host = '127.0.0.1'  # Dirección del servidor
    port = 5000  # Puerto
    
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)  # Escuchar hasta 2 conexiones
    
    print(f"Servidor escuchando en {host}:{port}")
    
    # Generar claves
    private_key, public_key = generate_keys()
    
    while True:
        conn, address = server_socket.accept()  # Aceptar nueva conexión
        print(f"Conexión desde: {str(address)}")
        
        # Crear un hilo para manejar al cliente
        client_thread = threading.Thread(target=handle_client, args=(conn, private_key))
        client_thread.start()

if __name__ == '__main__':
    server_program()
