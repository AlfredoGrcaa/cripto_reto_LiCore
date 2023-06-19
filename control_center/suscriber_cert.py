import hashlib
from hmac import HMAC
from hashlib import sha256
import json
from paho.mqtt import client as mqtt_client
import random
import ssl
import pandas as pd

Pcurve = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff  # The proven prime
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 # Number of points in the field
Acurve = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
Bcurve = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b  # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
GPoint = (Gx, Gy)  # This is our generator point. Tillions of dif ones possible

def modinv(a, n=Pcurve):  # Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low  # Use integer division operator for Python 3.x
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def ECadd(xp, yp, xq, yq):  # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq - yp) * modinv(xq - xp, Pcurve)) % Pcurve
    xr = (m * m - xp - xq) % Pcurve
    yr = (m * (xp - xr) - yp) % Pcurve
    return (xr, yr)


def ECdouble(xp, yp):  # EC point doubling, invented for EC. It doubles Point-P.
    LamNumer = 3 * xp * xp + Acurve
    LamDenom = 2 * yp
    Lam = (LamNumer * modinv(LamDenom, Pcurve)) % Pcurve
    xr = (Lam * Lam - 2 * xp) % Pcurve
    yr = (Lam * (xp - xr) - yp) % Pcurve
    return (xr, yr)


def EccMultiply(xs, ys, Scalar):  # Double & add. EC Multiplication, Not true multiplication
    if Scalar == 0 or Scalar >= N:
        raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    Qx, Qy = xs, ys
    for i in range(1, len(ScalarBin)):  # This is invented EC multiplication.
        Qx, Qy = ECdouble(Qx, Qy)
        if ScalarBin[i] == "1":
            Qx, Qy = ECadd(Qx, Qy, xs, ys)
    return (Qx, Qy)

def deterministic_generate_k(msghash, privkey):
    # Step 1: Prepare the key and message
    V = b'\x01' * 32
    K = b'\x00' * 32
    privkey = privkey.to_bytes(32, 'big')
    msghash = msghash.to_bytes(32, 'big')

    # Step 2: Generate the K value
    K = HMAC(K, V + b'\x00' + privkey + msghash, sha256).digest()
    V = HMAC(K, V, sha256).digest()
    K = HMAC(K, V + b'\x01' + privkey + msghash, sha256).digest()
    V = HMAC(K, V, sha256).digest()

    # Step 3: Convert the K value to an integer
    while True:
        t = b''
        while len(t) < 32:
            V = HMAC(K, V, sha256).digest()
            t += V
        k = int.from_bytes(t[:32], 'big')
        if k >= 1 and k < N:
            return k


def ECDSA_verify(message, r, s, xPublicKey, yPublicKey):
    # Step 1: Compute the deterministic k value
    HashOfThingToSign = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    k = deterministic_generate_k(HashOfThingToSign, xPublicKey)

    # Step 2: Compute w
    w = modinv(s, N)

    # Step 3: Compute u1 and u2
    xu1, yu1 = EccMultiply(Gx, Gy, (HashOfThingToSign * w) % N)
    xu2, yu2 = EccMultiply(xPublicKey, yPublicKey, (r * w) % N)

    # Step 4: Compute the verification point (x, y)
    x, y = ECadd(xu1, yu1, xu2, yu2)

    # Step 5: Check if r equals x
    return r == x

broker = 'cf1ce048.ala.us-east-1.emqxsl.com'
port = 8883
topic = "cripto_test"# generate client ID with pub prefix randomly
client_id = f'python-mqtt-{random.randint(0, 100)}'
# username = 'emqx'
# password = 'public'

# List to store received messages
received_messages = []

def connect_mqtt() -> mqtt_client:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code %d\n", rc)

    client = mqtt_client.Client(client_id)
    client.username_pw_set("auditor_1", "poner_una_contraseña_muy_segura1")
    client.on_connect = on_connect
    client.tls_set(ca_certs="C:\\Users\\Alfre\\Downloads\\emqxsl-ca.crt", 
                tls_version=ssl.PROTOCOL_TLSv1_2)

    client.connect(broker, port)

    
    return client


def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        message = f"Received `{msg.payload.decode()}` from `{msg.topic}` topic\n"
        received_messages.append(msg.payload.decode())  # Append the message to the list
        print(message)

    client.subscribe(topic)
    client.on_message = on_message


client = connect_mqtt()
subscribe(client)
# Run an infinite loop to continuously listen for MQTT messages
try:
    client.loop_forever()
except KeyboardInterrupt:
    client.disconnect()


received_messages_json = [json.loads(msg) for msg in received_messages]
#create another dictionary with encrypted_data and iv for all messages
messages_to_verify = []

for dict in received_messages_json:
    new_dict = {
        key: value
        for key, value in dict.items()
        if key in ('encrypted_data', 'iv')
    }
    messages_to_verify.append(new_dict)


xPublicKey, yPublicKey = 0x60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6, 0x7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299

valid_traces = []

for i in range(len(received_messages_json)):
    valid_signature = ECDSA_verify(str(messages_to_verify[i]), int(received_messages_json[i]['r'], 16), int(received_messages_json[i]['s'], 16), xPublicKey, yPublicKey)
    #print(valid_signature)
    if valid_signature:
        valid_traces.append(messages_to_verify[i])
        print("Valid Signature")
    else:
        print("Invalid Signature")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Decrypt the encrypted data using AES-CBC
def decrypt_data(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data
key = bytes.fromhex('05bb88dde58728d36ef20a116decd35cdbda24a4c2798050074d76c23fc47a73') #llave compartida previamente por el canal seguro #llave compartida previamente por el canal seguro

decrypted_data_valid_traces = []
# Decrypt and print each trace
for encrypted_trace in valid_traces:
    ciphertext = encrypted_trace['encrypted_data'].encode('latin-1')
    iv = encrypted_trace['iv'].encode('latin-1')
    decrypted_data = decrypt_data(key, iv, ciphertext)
    decrypted_data_valid_traces.append(decrypted_data.decode('latin-1'))
    print("Decrypted Data:", decrypted_data.decode())

# Remove the single quotes ('') from the strings
data = [s.replace("'", "") for s in decrypted_data_valid_traces]

# Convert the list of strings into a list of dictionaries
result = [json.loads("{" + s + "}") for s in decrypted_data_valid_traces]


# Assuming you have already obtained the 'result' list of dictionaries

# Create a DataFrame from the list of dictionaries
df = pd.DataFrame(result)

#export to a csv file
df.to_csv('decrypted_data_valid_traces.csv', index=False)