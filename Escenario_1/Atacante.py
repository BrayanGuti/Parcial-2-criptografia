import socket
import time
import math
import hashlib
from Crypto.Cipher import Salsa20
import base64

# Parámetros Diffie-Hellman (asumimos que el atacante los conoce)
# params = {
#     "p": 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903,
#     "g": 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579
# }

params = {
			"p": 227,
			"g": 12
		}

def baby_step_giant_step(g, h, p, max_time=3600):
    start_time = time.time()
    n = math.ceil(math.sqrt(p - 1))  # Tamaño óptimo para el algoritmo
    
    # Baby-step
    baby_steps = {pow(g, i, p): i for i in range(n)}
    
    # Giant-step
    factor = pow(g, n * (p - 2), p)
    for j in range(n):
        y = (h * pow(factor, j, p)) % p
        if y in baby_steps:
            x = j * n + baby_steps[y]
            if x < p:
                end_time = time.time()
                print(f"Clave privada encontrada: {x}")
                print(f"Tiempo transcurrido: {end_time - start_time:.2f} segundos")
                return x
        
        # Verificar si se ha excedido el tiempo máximo
        if time.time() - start_time > max_time:
            print("Tiempo máximo excedido. No se pudo encontrar la clave privada.")
            return None
    
    print("No se pudo encontrar la clave privada.")
    return None

def generate_symmetric_key(shared_key):
    shared_key_bytes = str(shared_key).encode()
    return hashlib.sha256(shared_key_bytes).digest()

def decrypt_message_salsa20(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.decode('utf-8')

def attack():
    # Simular la captura de las claves públicas y mensajes cifrados
    public_key_client = 112  # Ejemplo, en realidad sería capturado de la red
    public_key_server = 87  # Ejemplo, en realidad sería capturado de la red
    encrypted_message = "NqlkO7lSDdM+cV5E"  # Ejemplo, en realidad sería capturado de la red

    print("Iniciando ataque...")
    print(f"Clave pública del cliente: {public_key_client}")
    print(f"Clave pública del servidor: {public_key_server}")

    # Intentar recuperar la clave privada del cliente
    private_key_client = baby_step_giant_step(params["g"], public_key_client, params["p"])

    if private_key_client is not None:
        # Calcular la clave compartida
        shared_key = pow(public_key_server, private_key_client, params["p"])
        
        # Generar la clave simétrica
        symmetric_key = generate_symmetric_key(shared_key)
        print(f"Clave simétrica recuperada: {symmetric_key.hex()}")

        # Intentar descifrar el mensaje
        try:
            decrypted_message = decrypt_message_salsa20(symmetric_key, encrypted_message)
            print(f"Mensaje descifrado: {decrypted_message}")
        except Exception as e:
            print(f"Error al descifrar el mensaje: {e}")
    else:
        print("No se pudo recuperar la clave privada. El ataque ha fallado.")

if __name__ == '__main__':
    attack()