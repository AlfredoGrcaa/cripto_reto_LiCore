import hashlib
import random 

Pcurve = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff  # The proven prime
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  # Number of points in the field
Acurve = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
Bcurve = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b  # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
GPoint = (Gx, Gy)  # This is our generator point. Trillions of different ones possible

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

# Compute the shared secret for Party A

xPublicKeyB = 57765706760724140098123646751472600535326550109662776064875038005267580117034
yPublicKeyB = 70788982496352233443714385583970388108835637216643236078353504637029950751095

privKeyA = 46324957072193291895775492948656622280444675000543985253640679945070217163255

sharedSecretA = EccMultiply(xPublicKeyB, yPublicKeyB, privKeyA)
sharedSecretAx, sharedSecretAy = sharedSecretA

print("Shared SecretA = ", sharedSecretA)