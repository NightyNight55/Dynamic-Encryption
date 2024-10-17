import websockets
import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# 使用 RSA 公鑰加密 AES 密鑰
def encrypt_aes_key(aes_key, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

def pad_message(message):
    # 使用 PKCS7 填充訊息，確保它是 AES 區塊的倍數
    padder = padding.PKCS7(128).padder()  # 128 位代表 AES 的區塊大小（16 字節）
    padded_data = padder.update(message) + padder.finalize()
    return padded_data

async def send_message():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        # 接收伺服器發送的 RSA 公鑰
        public_key_pem = await websocket.recv()
        print(f"客戶端接收到的 RSA 公鑰:\n{public_key_pem}")

        # 生成 AES 金鑰
        aes_key = os.urandom(32)

        # 使用伺服器提供的 RSA 公鑰加密 AES 金鑰
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key_pem.encode())

        # 傳送加密後的 AES 金鑰到伺服器
        await websocket.send(encrypted_aes_key)

        # 手動輸入訊息
        message = input("請輸入要加密的訊息：").encode()

        # 使用 AES 密鑰加密訊息
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
        encryptor = cipher.encryptor()

        # 對訊息進行填充並加密
        padded_message = pad_message(message)
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

        # 發送加密訊息到伺服器
        await websocket.send(encrypted_message)

asyncio.run(send_message())
