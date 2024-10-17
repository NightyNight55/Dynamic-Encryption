import websockets
import asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# 動態生成 AES 密鑰
def generate_aes_key():
    key = os.urandom(32)  # AES-256 密鑰長度為 32 字節
    return key

def pad_message(message):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    return padded_data

def unpad_message(padded_message):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_message) + unpadder.finalize()
    return data

async def send_message():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        # 手動輸入要加密的訊息
        message = input("請輸入要加密的訊息：")

        # 生成 AES 密鑰
        aes_key = generate_aes_key()

        # 初始化 AES 加密器
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
        encryptor = cipher.encryptor()

        # 對訊息進行填充並加密
        padded_message = pad_message(message.encode())
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()

        # 傳送加密訊息
        await websocket.send(ciphertext)

        # 接收伺服器回覆的加密訊息（純位元組格式）
        response = await websocket.recv()

        # 先輸出收到的加密回覆
        print(f"收到伺服器回覆 (加密): {response}")

        # 解密伺服器回覆的訊息
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(response) + decryptor.finalize()

        # 去除填充，獲取原始訊息
        decrypted_message = unpad_message(decrypted_padded_message).decode()

        # 輸出解密後的訊息
        print(f"解密後的回覆: {decrypted_message}")

# 啟動事件循環，避免 DeprecationWarning
asyncio.run(send_message())
