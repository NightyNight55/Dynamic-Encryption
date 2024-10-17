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

# 對資料進行 RSA 加密
def encrypt_data_with_rsa(public_key, data):
    encrypted_data = public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# 伺服器處理邏輯
async def handle_client(websocket, path):
    print("新客戶端已連接")

    # 預存的 5 組資料
    stored_data = [
        "這是第 1 組資料".encode(),
        "這是第 2 組資料".encode(),
        "這是第 3 組資料".encode(),
        "這是第 4 組資料".encode(),
        "這是第 5 組資料".encode(),
    ]

    # 接收客戶端的 RSA 公鑰
    public_key_pem = await websocket.recv()
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    print("已接收到客戶端的 RSA 公鑰")

    # 等待客戶端請求選取的資料編號
    selection = await websocket.recv()
    print(f"客戶端選擇了第 {selection} 組資料")
    selected_index = int(selection) - 1  # 客戶端輸入的是 1 到 5，我們轉換為索引 0 到 4

    if 0 <= selected_index < len(stored_data):
        # 對選取的資料進行 RSA 加密
        selected_data = stored_data[selected_index]
        encrypted_data = encrypt_data_with_rsa(public_key, selected_data)
        print(f"已加密第 {selection} 組資料，準備發送給客戶端")

        # 使用 base64 編碼後傳送加密資料
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode()
        await websocket.send(encrypted_data_b64)
        print(f"已發送加密後的第 {selection} 組資料給客戶端")
    else:
        await websocket.send("無效的選擇，請輸入 1-5 之間的數字。")
        print("客戶端輸入了無效的選擇")

async def main():
    server = await websockets.serve(handle_client, "localhost", 8765)
    print("伺服器已啟動，等待客戶端連接...")
    await server.wait_closed()

asyncio.run(main())
