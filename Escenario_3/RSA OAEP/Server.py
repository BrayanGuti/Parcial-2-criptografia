import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generar par de claves RSA para el servidor
server_key = RSA.generate(2048)
server_public_key = server_key.publickey()

def handle_client(conn):
    print("Cliente conectado.")
    
    # Enviar la clave pública del servidor al cliente
    conn.send(server_public_key.export_key())
    
    # Recibir la clave pública del cliente
    client_public_key = RSA.import_key(conn.recv(1024))
    
    server_cipher = PKCS1_OAEP.new(server_key)
    client_cipher = PKCS1_OAEP.new(client_public_key)

    while True:
        encrypted_message = conn.recv(1024)  # Recibir mensaje encriptado del cliente
        if not encrypted_message:
            break
        
        # Desencriptar el mensaje
        message = server_cipher.decrypt(encrypted_message).decode()
        
        if message.lower() == 'exit':  # Si el cliente envía 'exit', cerrar la conexión
            break
        
        print(f"Cliente (desencriptado): {message}")
        
        # Enviar respuesta encriptada al cliente
        response = input("Tú: ")
        encrypted_response = client_cipher.encrypt(response.encode())
        conn.send(encrypted_response)

    conn.close()  # Cerrar la conexión con el cliente
    print("Cliente desconectado.")

def server_program():
    host = '127.0.0.1'  # Dirección del servidor
    port = 5000  # Puerto
    
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)  # Escuchar hasta 2 conexiones
    
    print(f"Servidor escuchando en {host}:{port}")
    
    while True:
        conn, address = server_socket.accept()  # Aceptar nueva conexión
        print(f"Conexión desde: {str(address)}")
        
        # Crear un hilo para manejar al cliente
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()

if __name__ == '__main__':
    server_program()