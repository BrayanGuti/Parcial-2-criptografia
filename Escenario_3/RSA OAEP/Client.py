import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def client_program():
    host = '127.0.0.1'  # Dirección del servidor
    port = 5000  # Puerto debe coincidir con el del servidor

    client_socket = socket.socket()
    client_socket.connect((host, port))

    print(f"Conectado al servidor en {host}:{port}")

    # Generar par de claves RSA para el cliente
    client_key = RSA.generate(2048)
    client_public_key = client_key.publickey()

    # Recibir la clave pública del servidor
    server_public_key = RSA.import_key(client_socket.recv(1024))
    
    # Enviar la clave pública del cliente al servidor
    client_socket.send(client_public_key.export_key())

    server_cipher = PKCS1_OAEP.new(server_public_key)
    client_cipher = PKCS1_OAEP.new(client_key)

    while True:
        message = input("Tú: ")  # Leer mensaje del usuario
        if message.lower() == 'exit':  # Salir si el usuario escribe 'exit'
            break
        
        # Encriptar el mensaje
        encrypted_message = server_cipher.encrypt(message.encode())
        
        # Enviar el mensaje encriptado al servidor
        client_socket.send(encrypted_message)
        
        # Recibir respuesta encriptada del servidor
        encrypted_response = client_socket.recv(1024)
        
        # Desencriptar la respuesta
        response = client_cipher.decrypt(encrypted_response).decode()
        
        print(f"Servidor (desencriptado): {response}")

    client_socket.close()  # Cerrar la conexión al finalizar

if __name__ == '__main__':
    client_program()