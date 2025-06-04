import asyncio
import websockets
import json

# Lưu 2 client, 1 client A và 1 client B
client_A = None
client_B = None

async def handler(ws):
    global client_A, client_B
    try:
        async for msg in ws:
            data = json.loads(msg)
            action = data.get("action")

            if action == "register":
                # client đăng ký loại A hay B
                role = data.get("role")
                if role == "A":
                    client_A = ws
                    await ws.send(json.dumps({"status": "registered", "role": "A"}))
                    print("Client A đăng ký")
                elif role == "B":
                    client_B = ws
                    await ws.send(json.dumps({"status": "registered", "role": "B"}))
                    print("Client B đăng ký")
                else:
                    await ws.send(json.dumps({"status": "error", "message": "Role không hợp lệ"}))

            elif action == "send_file_A" and client_B:
                # A gửi file, chuyển tiếp cho B
                await client_B.send(json.dumps({
                    "status": "file_from_A",
                    "filename": data.get("filename"),
                    "fileData": data.get("fileData"),
                    "fileHash": data.get("fileHash")
                }))
                await ws.send(json.dumps({"status": "file_received"}))
                print(f"File từ A chuyển đến B: {data.get('filename')}")

            elif action == "send_file_B" and client_A:
                # B gửi file, chuyển tiếp cho A
                await client_A.send(json.dumps({
                    "status": "file_from_B",
                    "filename": data.get("filename"),
                    "fileData": data.get("fileData"),
                    "fileHash": data.get("fileHash")
                }))
                await ws.send(json.dumps({"status": "file_received"}))
                print(f"File từ B chuyển đến A: {data.get('filename')}")

    except websockets.ConnectionClosed:
        print("Client đã ngắt kết nối")
    finally:
        if ws == client_A:
            client_A = None
            print("Client A đã ngắt kết nối")
        if ws == client_B:
            client_B = None
            print("Client B đã ngắt kết nối")

async def main():
    print("Server WebSocket chạy trên ws://192.168.1.100:8080")
    async with websockets.serve(handler, "0.0.0.0", 8080):
        await asyncio.Future()  # chạy vô hạn

if __name__ == "__main__":
    asyncio.run(main())
