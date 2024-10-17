import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

def main():
    host = '127.0.0.1'  # Dirección del servidor
    port = 5000  # Puerto
    
    client_socket = socket.socket()
    client_socket.connect((host, port))
    
    # Recibir clave pública del servidor
    pem = client_socket.recv(1024)
    public_key = serialization.load_pem_public_key(
        pem,
        backend=None
    )

    while True:
        # Enviar mensaje al servidor
        message = input("Tú: ")
        if message.lower() == 'exit':
            break
        ciphertext = encrypt(public_key, message.encode())
        client_socket.send(ciphertext)

        # Recibir respuesta cifrada del servidor
        response_ciphertext = client_socket.recv(1024)
        # Como el cliente no tiene la clave privada, no puede descifrar la respuesta aquí

    client_socket.close()  # Cerrar conexión
    print("Desconectado del servidor.")

if __name__ == '__main__':
    main()
