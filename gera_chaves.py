"""
Script para gerar um par de chaves RSA (privada e pública) para criptografia híbrida.
Cada chave será salva em arquivo PEM (private.pem e public.pem).
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ------------------ Geração da Chave Privada ------------------
# 🔹 Cria uma chave privada RSA de 2048 bits
# 🔹 public_exponent=65537 é seguro e eficiente
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# ------------------ Salvando a Chave Privada ------------------
# 🔹 Salva a chave privada em private.pem
# 🔹 Encoding PEM, formato TraditionalOpenSSL, sem senha (NoEncryption)
with open("private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# ------------------ Extraindo a Chave Pública ------------------
# 🔹 Extrai a chave pública da chave privada
public_key = private_key.public_key()

# ------------------ Salvando a Chave Pública ------------------
# 🔹 Salva a chave pública em public.pem
# 🔹 Encoding PEM, formato SubjectPublicKeyInfo
with open("public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# ------------------ Mensagem Final ------------------
# 🔹 Confirmação de que as chaves foram geradas
print("✅ Geradas: private.pem e public.pem")
