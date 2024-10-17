import websockets
import asyncio

async def echo(websocket, path):
    async for message in websocket:
        print(f"收到訊息: {message}")
        await websocket.send(message)  # 回覆原始的位元組訊息

async def main():
    start_server = await websockets.serve(echo, "localhost", 8765)
    print("伺服器正在等待連接...")
    await start_server.wait_closed()

asyncio.run(main())
