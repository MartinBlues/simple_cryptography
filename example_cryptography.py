import hashlib

# Generate a public-private key pair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Hashing using SHA-256
def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Usage example
message = "Hello, World!"
signature = private_key.sign(message.encode(), rsa.PSSPadding(), hashlib.sha256)

print("Message:", message)
print("Signature:", signature.hex())
print("Verified:", public_key.verify(signature, message.encode(), rsa.PSSPadding(), hashlib.sha256))
