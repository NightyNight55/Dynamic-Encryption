import websockets
import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# 生成 RSA 金鑰對
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 對加密資料進行 RSA 解密
def decrypt_data_with_rsa(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

async def send_message():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        # 生成 RSA 金鑰對
        private_key, public_key = generate_rsa_keys()
        print("已生成 RSA 金鑰對")

        # 將 RSA 公鑰發送給伺服器
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        await websocket.send(public_pem.decode())
        print("已將 RSA 公鑰發送給伺服器")

        # 手動輸入想要讀取的資料編號
        selection = input("請輸入想要讀取的資料編號 (1-5)：")
        await websocket.send(selection)
        print(f"已將選擇的資料編號 {selection} 發送給伺服器")

        # 接收伺服器回傳的加密資料
        encrypted_data_b64 = await websocket.recv()
        print(f"已接收到加密後的資料：{encrypted_data_b64}")

        encrypted_data = base64.b64decode(encrypted_data_b64)

        # 使用 RSA 私鑰解密資料
        decrypted_data = decrypt_data_with_rsa(private_key, encrypted_data)
        print(f"解密後的資料: {decrypted_data.decode()}")

asyncio.run(send_message())
