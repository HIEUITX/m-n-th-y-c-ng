# gui_server.py
import sys
import socket
import json
import base64
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget, QPushButton, QLabel, QHBoxLayout
from PyQt6.QtCore import QThread, pyqtSignal, QObject
from crypto_utils import *

# ***BỔ SUNG: Hàm tiện ích để gửi phản hồi JSON***
def send_json_response(sock, status, reason=""):
    response = {"status": status, "reason": reason}
    try:
        sock.sendall(json.dumps(response).encode('utf-8'))
    except Exception as e:
        # Ghi log lỗi nếu không gửi được, tránh làm sập server
        print(f"Lỗi khi gửi phản hồi JSON: {e}")

class ServerWorker(QObject):
    log_message = pyqtSignal(str)
    message_received = pyqtSignal(str, str) # user_id, message

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        self.sock = None
        self.conn = None

    def stop(self):
        self.running = False
        if self.conn:
            self.conn.close()
        # Tạo kết nối giả để thoát khỏi accept()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host if self.host != '0.0.0.0' else '127.0.0.1', self.port))
        except:
            pass
        self.log_message.emit("🔌 Server đã dừng.")


    def run(self):
        self.log_message.emit("🔑 Server: Đang tạo cặp khóa RSA...")
        server_private_key_pem, server_public_key_pem = generate_rsa_keys()
        server_private_key = load_rsa_private_key(server_private_key_pem)
        self.log_message.emit("🔑 Server: Đã tạo cặp khóa RSA.")

        current_session = {"aes_key": None, "user_id": None, "session_id": None}
        client_public_key = None # Lưu khóa công khai của client

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen()
            self.log_message.emit(f"📡 Server đang lắng nghe tại {self.host}:{self.port}")

            if not self.running: return
            self.conn, addr = self.sock.accept()
            if not self.running: return

            with self.conn:
                self.log_message.emit(f"🤝 Server: Đã kết nối bởi {addr}")
                # Giai đoạn 1: Handshake
                self.conn.sendall(server_public_key_pem)
                self.log_message.emit("📤 Server: Đã gửi khóa công khai cho Client.")

                client_public_key_pem = self.conn.recv(1024)
                client_public_key = load_rsa_public_key(client_public_key_pem)
                self.log_message.emit("📥 Server: Đã nhận khóa công khai của Client.")

                while self.running:
                    try:
                        data = self.conn.recv(4096)
                        if not data:
                            self.log_message.emit("❗️ Client đã ngắt kết nối.")
                            break

                        packet = json.loads(data.decode('utf-8'))
                        packet_type = packet.get("type")

                        if packet_type == "session_setup":
                            self.handle_session_setup(packet, client_public_key, server_private_key, current_session)
                        elif packet_type == "message":
                            # Truyền client_public_key vào để xác thực
                            self.handle_message(packet, current_session, client_public_key)

                    except (ConnectionResetError, ConnectionAbortedError):
                        self.log_message.emit("❗️ Client đã ngắt kết nối đột ngột.")
                        break
                    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
                        self.log_message.emit(f"❌ Lỗi xử lý gói tin: {e}")
                        send_json_response(self.conn, "NACK", "Packet format error")
                    except Exception as e:
                        self.log_message.emit(f"❌ Đã xảy ra lỗi không mong muốn: {e}")
                        break

    def handle_session_setup(self, packet, client_public_key, server_private_key, current_session):
        self.log_message.emit("\n📩 Server: Nhận được yêu cầu thiết lập session.")
        user_id = packet['user_id']
        session_id = base64.b64decode(packet['session_id'])
        encrypted_aes_key = base64.b64decode(packet['encrypted_aes_key'])
        signature = base64.b64decode(packet['signature'])

        metadata = f"{user_id}".encode('utf-8') + session_id
        if not verify_signature(metadata, signature, client_public_key):
            self.log_message.emit("   - ❌ LỖI: Xác thực chữ ký session thất bại!")
            send_json_response(self.conn, "NACK", "Session signature verification failed")
            return
        self.log_message.emit("   - ✅ Chữ ký session hợp lệ.")

        aes_key = decrypt_aes_key(encrypted_aes_key, server_private_key)
        self.log_message.emit("   - ✅ Đã giải mã khóa AES thành công.")

        current_session["aes_key"] = aes_key
        current_session["user_id"] = user_id
        current_session["session_id"] = session_id

        send_json_response(self.conn, "ACK_SETUP")
        self.log_message.emit("   - ✅ Session đã được thiết lập. Gửi ACK_SETUP.")

    def handle_message(self, packet, current_session, client_public_key):
        if not current_session["aes_key"] or not client_public_key:
            self.log_message.emit("   - ❌ LỖI: Nhận tin nhắn nhưng session chưa được thiết lập hoàn chỉnh.")
            send_json_response(self.conn, "NACK", "Session not established")
            return

        self.log_message.emit("\n📩 Server: Đã nhận gói tin nhắn mới.")
        iv = base64.b64decode(packet['iv'])
        cipher = base64.b64decode(packet['cipher'])
        received_hash = base64.b64decode(packet['hash'])
        signature = base64.b64decode(packet['signature']) # ***NHẬN CHỮ KÝ***

        data_to_verify = iv + cipher

        # Bước 1: Kiểm tra tính toàn vẹn (Hash)
        recalculated_hash = calculate_hash(data_to_verify)
        if recalculated_hash != received_hash:
            self.log_message.emit("   - ❌ LỖI: Tính toàn vẹn thất bại (Hash không khớp).")
            send_json_response(self.conn, "NACK", "Integrity check failed (hash mismatch)")
            return
        self.log_message.emit("   - ✅ Tính toàn vẹn được đảm bảo (Hash hợp lệ).")

        # ***BƯỚC 2 (MỚI): KIỂM TRA TÍNH XÁC THỰC (CHỮ KÝ)***
        if not verify_signature(data_to_verify, signature, client_public_key):
            self.log_message.emit("   - ❌ LỖI: Xác thực tin nhắn thất bại (Chữ ký không hợp lệ).")
            send_json_response(self.conn, "NACK", "Authentication failed (invalid signature)") # GỬI NACK_SIGNATURE
            return
        self.log_message.emit("   - ✅ Tính xác thực được đảm bảo (Chữ ký hợp lệ).")

        # Bước 3: Giải mã
        message = decrypt_message_aes(cipher, iv, current_session["aes_key"])
        self.message_received.emit(current_session['user_id'], message)

        # Bước 4: Gửi ACK
        send_json_response(self.conn, "ACK_MSG")
        self.log_message.emit("   - ✅ Tin nhắn hợp lệ. Đã gửi ACK cho client.")


# --- Phần giao diện ServerWindow không thay đổi ---
# (Dán code của ServerWindow ở đây)
class ServerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat - Server")
        self.setGeometry(100, 100, 500, 400)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.message_area = QTextEdit()
        self.message_area.setReadOnly(True)

        self.start_button = QPushButton("Bắt đầu Server")
        self.start_button.clicked.connect(self.start_server)
        self.stop_button = QPushButton("Dừng Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Log Hoạt Động:"))
        layout.addWidget(self.log_area)
        layout.addWidget(QLabel("Tin Nhắn Đã Giải Mã:"))
        layout.addWidget(self.message_area)
        layout.addLayout(button_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.thread = None
        self.worker = None

    def start_server(self):
        self.thread = QThread()
        self.worker = ServerWorker(host='0.0.0.0', port=65432)
        self.worker.moveToThread(self.thread)

        self.worker.log_message.connect(self.log_area.append)
        self.worker.message_received.connect(self.display_message)

        self.thread.started.connect(self.worker.run)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_area.clear()
        self.message_area.clear()

    def stop_server(self):
        if self.worker:
            self.worker.stop()
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def display_message(self, user_id, message):
        self.message_area.append(f"[{user_id}]: {message}")

    def closeEvent(self, event):
        self.stop_server()
        super().closeEvent(event)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ServerWindow()
    window.show()
    sys.exit(app.exec())