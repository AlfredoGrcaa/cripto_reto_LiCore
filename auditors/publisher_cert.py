import paho.mqtt.client as mqtt
import random
import json
import time
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import hashlib
from hmac import HMAC
from hashlib import sha256



broker = 'cf1ce048.ala.us-east-1.emqxsl.com'
port = 8883
publish_topic = "cripto_test"
subscribe_topic = "cripto_test"

client_id = f'python-mqtt-{random.randint(0, 100)}'

def connect_mqtt() -> mqtt.Client:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code", rc)

    client = mqtt.Client(client_id)
    client.on_connect = on_connect

    client.username_pw_set("auditor_1", "poner_una_contraseña_muy_segura1")
    # Enable SSL/TLS
    client.tls_set(ca_certs="C:\\Users\\Alfre\\Downloads\\emqxsl-ca.crt", 
                tls_version=ssl.PROTOCOL_TLSv1_2)
    #client.tls_insecure_set(True)  # Accept self-signed certificates without verification


    # Set MQTT broker address and port
    client.connect(broker, port)
    return client

def publish(client: mqtt.Client, data):
    msg_count = 0
    while True:
        time.sleep(5)
        msg = json.dumps(data[msg_count])
        result = client.publish(publish_topic, msg)
        status = result[0]
        if status == mqtt.MQTT_ERR_SUCCESS:
            print(f"Published message {msg_count + 1} of {len(data)}")
        else:
            print(f"Failed to publish message {msg_count + 1}")
        msg_count += 1
        if msg_count >= len(data):
            break

# Example traces data
example_traces = [
    {"trace_id": "011", "timestamp": "2013-11-02T00:00:00Z", "C(0)/P(1)": "0", "value": 58.0},
    {"trace_id": "012", "timestamp": "2013-11-02T00:15:00Z", "C(0)/P(1)": "0", "value": 75.0},
    {"trace_id": "013", "timestamp": "2013-11-02T00:30:00Z", "C(0)/P(1)": "0", "value": 65.0},
    {"trace_id": "014", "timestamp": "2013-11-02T00:45:00Z", "C(0)/P(1)": "0", "value": 0.08},
    {"trace_id": "015", "timestamp": "2013-11-02T01:00:00Z", "C(0)/P(1)": "0", "value": 67.0},
    {"trace_id": "016", "timestamp": "2013-11-02T01:15:00Z", "C(0)/P(1)": "0", "value": 69.0},
    {"trace_id": "017", "timestamp": "2013-11-02T01:30:00Z", "C(0)/P(1)": "0", "value": 0.07},
    {"trace_id": "018", "timestamp": "2013-11-02T01:45:00Z", "C(0)/P(1)": "0", "value": 73.0},
    {"trace_id": "019", "timestamp": "2013-11-02T02:00:00Z", "C(0)/P(1)": "0", "value": 68.0},
    {"trace_id": "0110", "timestamp": "2013-11-02T02:15:00Z", "C(0)/P(1)": "0", "value": 0.06}
]

# Generate a unique IV for each trace
def generate_iv():
    iv_length = 16  # IV length in bytes (recommended 16 bytes for AES)
    iv = os.urandom(iv_length)
    return iv

# Encrypt data using AES-CBC with a unique IV for each trace
def encrypt_data(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Example usage
key = bytes.fromhex('05bb88dde58728d36ef20a116decd35cdbda24a4c2798050074d76c23fc47a73')

# Original traces
traces = [
    b'"trace_id": "011", "timestamp": "2013-11-02T00:00:00Z", "C(0)/P(1)": "0", "value": 58.0',
    b'"trace_id": "012", "timestamp": "2013-11-02T00:15:00Z", "C(0)/P(1)": "0", "value": 75.0',
    b'"trace_id": "013", "timestamp": "2013-11-02T00:30:00Z", "C(0)/P(1)": "0", "value": 65.0',
    b'"trace_id": "014", "timestamp": "2013-11-02T00:45:00Z", "C(0)/P(1)": "0", "value": 0.08',
    b'"trace_id": "015", "timestamp": "2013-11-02T01:00:00Z", "C(0)/P(1)": "0", "value": 67.0',
    b'"trace_id": "016", "timestamp": "2013-11-02T01:15:00Z", "C(0)/P(1)": "0", "value": 69.0',
    b'"trace_id": "017", "timestamp": "2013-11-02T01:30:00Z", "C(0)/P(1)": "0", "value": 0.07',
    b'"trace_id": "018", "timestamp": "2013-11-02T01:45:00Z", "C(0)/P(1)": "0", "value": 73.0',
    b'"trace_id": "019", "timestamp": "2013-11-02T02:00:00Z", "C(0)/P(1)": "0", "value": 68.0',
    b'"trace_id": "0110", "timestamp": "2013-11-02T02:15:00Z", "C(0)/P(1)": "0", "value": 0.06'
]

# Encrypt and store each trace individually
encrypted_traces = []
for trace in traces:
    iv = generate_iv()
    ciphertext = encrypt_data(key, iv, trace)
    encrypted_trace = {
        'encrypted_data': ciphertext.decode('latin-1'),
        'iv': iv.decode('latin-1')
    }
    encrypted_traces.append(encrypted_trace)


Pcurve = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff  # The proven prime
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 # Number of points in the field
Acurve = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
Bcurve = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b  # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
GPoint = (Gx, Gy)  # This is our generator point. Tillions of dif ones possible

# Individual Transaction/Personal Information
privKey = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721  # replace with any private key
#RandNum = 28695618543805844332113829720373285210420739438570883203839696518176414791234  # replace with a truly random number
message = 'sample'
HashOfThingToSign = int(hashlib.sha256(message.encode()).hexdigest(), 16)



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

def ECDSA_sign(message, privKey):
    # Step 1: Generate the deterministic k value
    HashOfThingToSign = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    k = deterministic_generate_k(HashOfThingToSign, privKey)

    # Step 2: Compute the public key
    xPublicKey, yPublicKey = EccMultiply(Gx, Gy, privKey)

    # Step 3: Compute r
    xRandSignPoint, yRandSignPoint = EccMultiply(Gx, Gy, k)
    r = xRandSignPoint % N

    # Step 4: Compute s
    s = ((HashOfThingToSign + r * privKey) * (modinv(k, N))) % N

    return r, s

xPublicKey, yPublicKey = EccMultiply(Gx, Gy, privKey)

# Encrypt and store each trace individually
signed_encrypted_traces = []
for trace in encrypted_traces:
    r, s = ECDSA_sign(str(trace), privKey)
    signed_encrypted_trace = {
        'encrypted_data': trace['encrypted_data'],
        'iv': trace['iv'],
        'r': hex(r),
        's': hex(s),
    }
    signed_encrypted_traces.append(signed_encrypted_trace)


client = connect_mqtt()
client.loop_start()

# Publish example traces
publish(client, signed_encrypted_traces)