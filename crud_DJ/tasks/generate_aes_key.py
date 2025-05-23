import os

# Generar una clave AES de 32 bytes (AES-256)
key = os.urandom(32)  # 32 bytes = 256 bits
iv = os.urandom(16)   # 16 bytes = 128 bits (para CBC)

# Guardar en formato legible (base64)
print(f"AES_KEY = {key.hex()}")
print(f"AES_IV = {iv.hex()}")
