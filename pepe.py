import random

def diffie_hellman(params):
    # Seleccionamos los valores de p, q, g de los parámetros proporcionados
    p = params["p"]
    q = params["q"]
    g = params["g"]

    # Cada usuario selecciona una clave privada aleatoria menor que q
    private_key_a = random.randint(1, q-1)
    private_key_b = random.randint(1, q-1)

    # Claves públicas calculadas con g^privado mod p
    public_key_a = pow(g, private_key_a, p)
    public_key_b = pow(g, private_key_b, p)

    # Cálculo de la clave compartida
    shared_secret_a = pow(public_key_b, private_key_a, p)
    shared_secret_b = pow(public_key_a, private_key_b, p)

    assert shared_secret_a == shared_secret_b, "Las claves compartidas no coinciden!"

    # Devolver las claves privadas, públicas y la clave compartida
    return {
        "private_key_a": private_key_a,
        "private_key_b": private_key_b,
        "public_key_a": public_key_a,
        "public_key_b": public_key_b,
        "shared_secret": shared_secret_a
    }

# Ejemplo de uso con los parámetros provistos
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

# Seleccionar los primeros parámetros para el test
result = diffie_hellman(parameters_list[3])
print(result)
