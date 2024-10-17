import random

# Función para generar claves del lado del servidor
def diffie_hellman_server(params):
    p = params["p"]
    g = params["g"]

    # Servidor elige una clave privada aleatoria
    private_key_server = random.randint(1, p - 1)

    # Clave pública del servidor (A = g^a mod p)
    public_key_server = pow(g, private_key_server, p)

    # Devuelve la clave privada y la clave pública
    return private_key_server, public_key_server

# Función para calcular la clave compartida en el servidor
def diffie_hellman_compute_shared_key_server(private_key_server, public_key_client, p):
    # Cálculo de la clave compartida en el servidor (K = B^a mod p)
    shared_key_server = pow(public_key_client, private_key_server, p)
    return shared_key_server

# Función para generar claves del lado del cliente
def diffie_hellman_client(params):
    p = params["p"]
    g = params["g"]

    # Cliente elige una clave privada aleatoria
    private_key_client = random.randint(1, p - 1)

    # Clave pública del cliente (B = g^b mod p)
    public_key_client = pow(g, private_key_client, p)

    # Devuelve la clave privada y la clave pública
    return private_key_client, public_key_client

# Función para calcular la clave compartida en el cliente
def diffie_hellman_compute_shared_key_client(private_key_client, public_key_server, p):
    # Cálculo de la clave compartida en el cliente (K = A^b mod p)
    shared_key_client = pow(public_key_server, private_key_client, p)
    return shared_key_client

# Función de prueba adaptada para aceptar parámetros dinámicos
def test_diffie_hellman(params):
    p = params["p"]
    g = params["g"]

    # 1. Servidor genera sus claves
    private_key_server, public_key_server = diffie_hellman_server(params)

    # 2. Cliente genera sus claves
    private_key_client, public_key_client = diffie_hellman_client(params)

    # 3. Clave compartida en el servidor
    shared_key_server = diffie_hellman_compute_shared_key_server(private_key_server, public_key_client, p)

    # 4. Clave compartida en el cliente
    shared_key_client = diffie_hellman_compute_shared_key_client(private_key_client, public_key_server, p)

    # Comprobación
    assert shared_key_server == shared_key_client, f"Las claves no coinciden: servidor={shared_key_server}, cliente={shared_key_client}"
    print(f"Prueba exitosa: Clave compartida = {shared_key_server}")

# Lista de parámetros proporcionados
parameters_list = [
    {"p": 227, "q": 113, "g": 12},
    {"p": 51047, "q": 25523, "g": 93},
    {"p": 14330819, "q": 7165409, "g": 1970788},
    {"p": 13926985804350796967, "q": 6963492902175398483, "g": 4460925131279825939},
    {
        "p": 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903,
        "q": 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951,
        "g": 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579
    }
]

# Ejecutar la prueba con uno de los parámetros grandes
test_diffie_hellman(parameters_list[3])
