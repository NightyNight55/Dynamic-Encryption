import websockets
import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# 生成 RSA 金鑰對（伺服器端）
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 生成 AES 金鑰
def generate_aes_key():
    key = os.urandom(32)  # AES-256 密鑰長度為 32 字節
    return key

async def handle_client(websocket, path):
    # 生成 RSA 金鑰對
    private_key, public_key = generate_rsa_keys()

    # 將 RSA 公鑰序列化並發送給客戶端
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    await websocket.send(public_pem.decode())

    # 生成 AES 密鑰
    aes_key = generate_aes_key()

    # 客戶端將用 RSA 公鑰加密 AES 密鑰，等待客戶端傳回加密的 AES 密鑰
    encrypted_aes_key = await websocket.recv()

    # 使用 RSA 私鑰解密 AES 密鑰
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 現在伺服器端可以使用解密後的 AES 密鑰進行加解密操作
    print(f"伺服器解密後的 AES 密鑰: {decrypted_aes_key.hex()}")

    # 伺服器等待並接收來自客戶端的加密訊息
    encrypted_message = await websocket.recv()

    # 使用 AES 解密訊息
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    print(f"伺服器接收到的解密訊息: {decrypted_message.decode()}")

async def main():
    server = await websockets.serve(handle_client, "localhost", 8765)
    print("伺服器已啟動，等待客戶端連接...")
    await server.wait_closed()

asyncio.run(main())
