# gui_client.py
import sys
import socket
import json
import base64
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTextEdit, QVBoxLayout,
                             QWidget, QPushButton, QLabel, QLineEdit, QHBoxLayout, QMessageBox)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, QSocketNotifier
from crypto_utils import *

class ClientWorker(QObject):
    log_message = pyqtSignal(str)
    connection_status = pyqtSignal(bool, str)

    def __init__(self, host, port, user_id):
        super().__init__()
        self.host = host
        self.port = port
        self.user_id = user_id
        self.sock = None
        self.aes_key = None
        self.notifier = None
        self.client_private_key = None # Lưu khóa riêng để ký tin nhắn

    def connect_and_run(self):
        try:
            self.log_message.emit("🔑 Client: Đang tạo cặp khóa RSA...")
            client_private_key_pem, client_public_key_pem = generate_rsa_keys()
            self.client_private_key = load_rsa_private_key(client_private_key_pem)
            self.log_message.emit("🔑 Client: Đã tạo cặp khóa RSA.")

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.log_message.emit(f"🤝 Client: Đã kết nối đến server tại {self.host}:{self.port}")

            self.notifier = QSocketNotifier(self.sock.fileno(), QSocketNotifier.Type.Read, self)
            self.notifier.activated.connect(self.on_data_ready)

            # Giai đoạn 1: Handshake
            server_public_key_pem = self.sock.recv(1024)
            server_public_key = load_rsa_public_key(server_public_key_pem)
            self.log_message.emit("📥 Client: Đã nhận khóa công khai của Server.")
            self.sock.sendall(client_public_key_pem)
            self.log_message.emit("📤 Client: Đã gửi khóa công khai cho Server.")

            # Giai đoạn 2: Thiết lập Session
            self.setup_session(server_public_key)

        except ConnectionRefusedError:
            self.connection_status.emit(False, "Lỗi: Không thể kết nối. Server có đang chạy không?")
        except Exception as e:
            self.connection_status.emit(False, f"Lỗi kết nối: {e}")
            self.stop()

    def setup_session(self, server_public_key):
        self.log_message.emit("\n🚀 Client: Bắt đầu thiết lập session...")
        self.aes_key = get_random_bytes(32)
        session_id = os.urandom(16)

        metadata = f"{self.user_id}".encode('utf-8') + session_id
        signature = sign_data(metadata, self.client_private_key)
        self.log_message.emit("   - Đã ký metadata (UserID + SessionID).")

        encrypted_aes_key = encrypt_aes_key(self.aes_key, server_public_key)
        self.log_message.emit("   - Đã mã hóa khóa AES bằng khóa công khai của Server.")

        setup_packet = {
            "type": "session_setup",
            "user_id": self.user_id,
            "session_id": base64.b64encode(session_id).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        self.sock.sendall(json.dumps(setup_packet).encode('utf-8'))

    def send_message(self, message_text):
        if not self.sock or not self.aes_key or not self.client_private_key:
            self.log_message.emit("❗️ Lỗi: Chưa kết nối hoặc session chưa sẵn sàng. Không thể gửi tin.")
            return

        try:
            # Mã hóa
            iv, ciphertext = encrypt_message_aes(message_text, self.aes_key)
            data_to_protect = iv + ciphertext

            # Tính hash để kiểm tra toàn vẹn
            message_hash = calculate_hash(data_to_protect)

            # ***BỔ SUNG: Ký vào dữ liệu (IV + ciphertext) để xác thực***
            signature = sign_data(data_to_protect, self.client_private_key)

            # Tạo gói tin hoàn chỉnh theo yêu cầu
            message_packet = {
                "type": "message",
                "iv": base64.b64encode(iv).decode('utf-8'),
                "cipher": base64.b64encode(ciphertext).decode('utf-8'),
                "hash": base64.b64encode(message_hash).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8') # ***ĐÃ THÊM***
            }

            self.sock.sendall(json.dumps(message_packet).encode('utf-8'))
            self.log_message.emit(f"📤 Đã gửi: '{message_text}' (Đã ký & mã hóa)")
        except Exception as e:
            self.log_message.emit(f"❌ Lỗi khi gửi tin: {e}")
            self.stop()

    def on_data_ready(self):
        try:
            response_data = self.sock.recv(2048)
            if not response_data:
                self.log_message.emit("❗️ Server đã đóng kết nối.")
                self.stop()
                return

            response_str = response_data.decode('utf-8')
            # ***CẬP NHẬT: Xử lý phản hồi JSON***
            try:
                packet = json.loads(response_str)
                status = packet.get("status")
                if status == "ACK_SETUP":
                    self.log_message.emit("✅ Client: Session đã được thiết lập thành công.")
                    self.connection_status.emit(True, f"Đã kết nối với tư cách {self.user_id}")
                elif status == "ACK_MSG":
                    self.log_message.emit(f"✔️ Server đã nhận thành công tin nhắn.")
                elif status == "NACK":
                     self.log_message.emit(f"❌ Server từ chối: {packet.get('reason')}")
                else:
                    self.log_message.emit(f"💬 Phản hồi không rõ từ Server: {response_str}")
            except json.JSONDecodeError:
                 self.log_message.emit(f"💬 Phản hồi không phải JSON từ Server: {response_str}")

        except Exception as e:
            self.log_message.emit(f"❗️ Lỗi nhận dữ liệu: {e}")
            self.stop()

    def stop(self):
        if self.notifier:
            self.notifier.setEnabled(False)
        if self.sock:
            self.sock.close()
            self.sock = None
        self.connection_status.emit(False, "Đã ngắt kết nối")

# --- Phần giao diện ClientWindow không thay đổi ---
# (Dán code của ClientWindow ở đây)
class ClientWindow(QMainWindow):
    send_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat - Client")
        self.setGeometry(700, 100, 500, 400)

        # Widgets
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Nhập tin nhắn tại đây...")
        self.send_button = QPushButton("Gửi")

        self.ip_input = QLineEdit("127.0.0.1")
        self.port_input = QLineEdit("65432")
        self.user_input = QLineEdit("Client_01")
        self.connect_button = QPushButton("Kết nối")
        self.disconnect_button = QPushButton("Ngắt kết nối")
        self.status_label = QLabel("Trạng thái: Chưa kết nối")

        # Layout
        connection_layout = QHBoxLayout()
        connection_layout.addWidget(QLabel("Server IP:"))
        connection_layout.addWidget(self.ip_input)
        connection_layout.addWidget(QLabel("Port:"))
        connection_layout.addWidget(self.port_input)
        connection_layout.addWidget(QLabel("User ID:"))
        connection_layout.addWidget(self.user_input)
        connection_layout.addWidget(self.connect_button)
        connection_layout.addWidget(self.disconnect_button)

        message_layout = QHBoxLayout()
        message_layout.addWidget(self.message_input)
        message_layout.addWidget(self.send_button)

        layout = QVBoxLayout()
        layout.addLayout(connection_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(QLabel("Log Hoạt Động:"))
        layout.addWidget(self.log_area)
        layout.addLayout(message_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Connections
        self.connect_button.clicked.connect(self.connect_to_server)
        self.disconnect_button.clicked.connect(self.disconnect_from_server)
        self.send_button.clicked.connect(self.send_message)
        self.message_input.returnPressed.connect(self.send_message)

        self.thread = None
        self.worker = None
        self.update_ui_status(False)

    def update_ui_status(self, connected):
        self.connect_button.setEnabled(not connected)
        self.disconnect_button.setEnabled(connected)
        self.send_button.setEnabled(connected)
        self.message_input.setEnabled(connected)
        self.ip_input.setEnabled(not connected)
        self.port_input.setEnabled(not connected)
        self.user_input.setEnabled(not connected)

    def connect_to_server(self):
        host = self.ip_input.text()
        port_text = self.port_input.text()
        user_id = self.user_input.text()

        if not all([host, port_text, user_id]):
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập đầy đủ thông tin.")
            return

        try:
            port = int(port_text)
        except ValueError:
            QMessageBox.warning(self, "Lỗi", "Port phải là một con số.")
            return

        self.log_area.clear()
        self.status_label.setText("Trạng thái: Đang kết nối...")

        self.thread = QThread()
        self.worker = ClientWorker(host, port, user_id)
        self.worker.moveToThread(self.thread)

        self.worker.log_message.connect(self.log_area.append)
        self.worker.connection_status.connect(self.on_connection_status_changed)

        self.send_signal.connect(self.worker.send_message)

        self.thread.started.connect(self.worker.connect_and_run)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def on_connection_status_changed(self, is_connected, message):
        self.status_label.setText(f"Trạng thái: {message}")
        self.update_ui_status(is_connected)

    def send_message(self):
        message = self.message_input.text()
        if message and self.worker:
            self.send_signal.emit(message)
            self.message_input.clear()

    def disconnect_from_server(self):
        if self.worker:
            try:
                self.send_signal.disconnect(self.worker.send_message)
            except TypeError:
                pass
            self.worker.stop()
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()

        self.update_ui_status(False)
        self.status_label.setText("Trạng thái: Đã ngắt kết nối")


    def closeEvent(self, event):
        self.disconnect_from_server()
        super().closeEvent(event)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ClientWindow()
    window.show()
    sys.exit(app.exec())