// server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid'); // Để tạo ID duy nhất cho file

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { // Thêm cấu hình CORS cho Socket.IO để tránh lỗi cross-origin
        origin: "http://localhost:3000", // Hoặc "*" nếu bạn muốn cho phép từ mọi nguồn (ít an toàn hơn)
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Đảm bảo thư mục 'uploads' tồn tại
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
    console.log(`Server: Đã tạo thư mục uploads tại: ${UPLOAD_DIR}`);
} else {
    console.log(`Server: Thư mục uploads đã tồn tại: ${UPLOAD_DIR}`);
}

// Cấu hình Multer để lưu trữ file
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        // Sử dụng uuid để đảm bảo tên file duy nhất trên server
        const fileExtension = path.extname(file.originalname);
        const fileName = `${uuidv4()}${fileExtension}`;
        cb(null, fileName);
    }
});
const upload = multer({ storage: storage });

// Biến toàn cục để lưu trữ cặp khóa RSA và danh sách các file đang chờ
let privateKey;
let publicKey;
const pendingFiles = {}; // Lưu trữ { fileId: { filename, filePath, fileHash, signature } }

// Hàm tạo cặp khóa RSA
function generateKeyPair() {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 2048, // Độ dài khóa (bits)
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        }, (err, pubKey, privKey) => {
            if (err) {
                console.error('Server: LỖI KHI TẠO CẶP KHÓA RSA:', err);
                return reject(err);
            }
            publicKey = pubKey;
            privateKey = privKey;
            console.log('Server: Cặp khóa RSA đã được tạo thành công.');
            console.log('Server: KHÓA CÔNG KHAI (DÙNG CHO receiver.html):\n', publicKey);
            resolve();
        });
    });
}

// Khởi tạo cặp khóa khi server khởi động
generateKeyPair().catch(error => {
    console.error('Server: KHÔNG THỂ KHỞI TẠO CẶP KHÓA RSA. Vui lòng kiểm tra môi trường Node.js:', error);
    process.exit(1); // Thoát nếu không tạo được khóa
});

// Middleware để phục vụ các file tĩnh (HTML, CSS, JS)
app.use(express.static(__dirname)); // Phục vụ các file trong thư mục hiện tại

// Route cho trang chính
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Xử lý yêu cầu ký số từ người gửi
io.on('connection', (socket) => {
    console.log(`Server Socket: Client ĐÃ KẾT NỐI: ${socket.id}`);

    // Xử lý sự kiện tham gia phòng (dành cho người nhận)
    socket.on('join_room', (data) => {
        socket.join(data.room);
        console.log(`Server Socket: Client ${socket.id} ĐÃ THAM GIA phòng: ${data.room}`);
        // Nếu là receiver_room, gửi danh sách các file đang chờ (nếu có)
        if (data.room === 'receiver_room') {
            const currentPendingFiles = Object.values(pendingFiles).map(file => ({
                file_id: file.fileId,
                filename: file.filename,
                file_hash: file.fileHash,
                signature: file.signature,
                download_url: `/download/${file.fileId}` // Đảm bảo URL tải xuống đúng
            }));
            socket.emit('pending_files_list', { files: currentPendingFiles });
            console.log(`Server Socket: Đã gửi ${currentPendingFiles.length} file đang chờ đến người nhận mới.`);
        }
    });

    // Sự kiện yêu cầu ký hash từ người gửi
    socket.on('request_signature', (data) => {
        const { hash } = data;
        console.log(`Server Socket: Nhận yêu cầu ký hash từ client ${socket.id}. Hash: ${hash.substring(0, 30)}...`);

        if (!hash) {
            console.error('Server Socket: Lỗi - Không có hash để ký.');
            socket.emit('signature_result', { status: 'ERROR', message: 'Không có hash để ký.' });
            return;
        }
        if (!privateKey) {
            console.error('Server Socket: Lỗi - Khóa riêng chưa sẵn sàng.');
            socket.emit('signature_result', { status: 'ERROR', message: 'Server chưa sẵn sàng để ký (khóa riêng chưa tạo).' });
            return;
        }

        try {
            const sign = crypto.createSign('SHA256');
            sign.update(hash); // Ký trên hash của file
            const signature = sign.sign(privateKey, 'hex'); // Ký bằng khóa riêng và trả về dạng hex

            console.log(`Server Socket: Đã ký hash thành công. Chữ ký: ${signature.substring(0, 30)}...`);
            socket.emit('signature_result', { status: 'SUCCESS', signature: signature });
        } catch (error) {
            console.error('Server Socket: Lỗi khi ký hash:', error);
            socket.emit('signature_result', { status: 'ERROR', message: 'Lỗi trong quá trình ký số.', error: error.message });
        }
    });

    socket.on('disconnect', () => {
        console.log(`Server Socket: Client ĐÃ NGẮT KẾT NỐI: ${socket.id}`);
    });

    socket.on('error', (error) => {
        console.error(`Server Socket: Lỗi Socket.IO từ client ${socket.id}:`, error);
    });
});


// Endpoint để người gửi tải file đã được ký lên server
app.post('/upload_with_signature', upload.single('file'), (req, res) => {
    console.log('Server HTTP: Nhận yêu cầu POST /upload_with_signature');
    if (!req.file) {
        console.error('Server HTTP: Lỗi - Không có file được tải lên.');
        return res.status(400).json({ status: 'ERROR', message: 'Không có file được tải lên.' });
    }

    const fileId = uuidv4(); // ID duy nhất cho file
    const originalFilename = req.file.originalname;
    const filePath = req.file.path; // Đường dẫn file tạm thời được Multer lưu
    const clientProvidedHash = req.body.fileHash;
    const clientProvidedSignature = req.body.signature;

    console.log(`Server HTTP: Nhận được file "${originalFilename}" (ID: ${fileId}) từ người gửi.`);
    console.log(`Server HTTP: Client hash: ${clientProvidedHash}, Client signature: ${clientProvidedSignature.substring(0, 30)}...`);

    // Bước 1: Tính toán lại hash của file trên server để đảm bảo tính toàn vẹn
    fs.readFile(filePath, async (err, fileBuffer) => {
        if (err) {
            console.error('Server HTTP: Lỗi khi đọc file đã tải lên:', err);
            return res.status(500).json({ status: 'ERROR', message: 'Lỗi khi xử lý file.' });
        }

        const serverCalculatedHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        console.log('Server HTTP: Hash của file sau khi tải lên (server-side):', serverCalculatedHash);

        // Bước 2: Xác minh chữ ký số mà người gửi cung cấp (tùy chọn, nhưng tốt cho bảo mật)
        try {
            if (!publicKey) {
                throw new Error('Khóa công khai của server chưa sẵn sàng để xác minh.');
            }
            const verify = crypto.createVerify('SHA256');
            verify.update(clientProvidedHash); // Xác minh chữ ký trên hash mà client đã gửi
            const isSignatureValidOnServer = verify.verify(publicKey, clientProvidedSignature, 'hex');

            console.log('Server HTTP: Xác minh chữ ký từ client (trên hash) - Kết quả:', isSignatureValidOnServer);

            if (!isSignatureValidOnServer || serverCalculatedHash !== clientProvidedHash) {
                // Nếu chữ ký không hợp lệ HOẶC hash của file trên server không khớp với hash mà client cung cấp
                console.error('Server HTTP: XÁC MINH FILE THẤT BẠI: Chữ ký không hợp lệ HOẶC Hash không khớp.');
                fs.unlink(filePath, (unlinkErr) => { // Xóa file không hợp lệ
                    if (unlinkErr) console.error('Server HTTP: Lỗi khi xóa file không hợp lệ:', unlinkErr);
                });
                return res.status(403).json({ status: 'ERROR', message: 'Xác minh chữ ký hoặc hash của file thất bại. File có thể đã bị giả mạo.' });
            }

            // Nếu mọi thứ OK, lưu thông tin file vào danh sách pendingFiles
            pendingFiles[fileId] = {
                fileId: fileId,
                filename: originalFilename,
                filePath: filePath, // Đường dẫn file trên server
                fileHash: serverCalculatedHash, // Hash đã được server xác nhận
                signature: clientProvidedSignature // Chữ ký đã được server xác nhận
            };

            // --- RẤT QUAN TRỌNG: PHÁT SỰ KIỆN CHO NGƯỜI NHẬN ---
            io.to('receiver_room').emit('new_file_available', {
                file_id: fileId,
                filename: originalFilename,
                file_hash: serverCalculatedHash, // Gửi hash đã được server tính toán lại và xác nhận
                signature: clientProvidedSignature, // Gửi chữ ký đã được server xác nhận
                download_url: `/download/${fileId}` // Cung cấp URL tải xuống
            });
            console.log(`Server HTTP: Đã thêm file "${originalFilename}" vào danh sách chờ và thông báo cho người nhận qua Socket.IO.`);
            res.json({ status: 'SUCCESS', message: 'File đã được tải lên và ký số thành công.', fileId: fileId });

        } catch (error) {
            console.error('Server HTTP: Lỗi khi xác minh chữ ký file:', error);
            fs.unlink(filePath, (unlinkErr) => {
                if (unlinkErr) console.error('Server HTTP: Lỗi khi xóa file bị lỗi xác minh:', unlinkErr);
            });
            res.status(500).json({ status: 'ERROR', message: 'Lỗi nội bộ khi xác minh chữ ký.', error: error.message });
        }
    });
});

// Endpoint để người nhận tải file
app.get('/download/:fileId', (req, res) => {
    const fileId = req.params.fileId;
    const fileInfo = pendingFiles[fileId];

    if (!fileInfo) {
        console.log(`Server HTTP: Không tìm thấy file với ID: ${fileId}`);
        return res.status(404).send('File không tìm thấy hoặc đã bị xóa.');
    }

    // Đảm bảo đường dẫn file an toàn và tồn tại
    const filePath = fileInfo.filePath;
    if (fs.existsSync(filePath) && filePath.startsWith(UPLOAD_DIR)) {
        console.log(`Server HTTP: Đang phục vụ file: ${fileInfo.filename} (ID: ${fileId}) từ ${filePath}`);
        res.download(filePath, fileInfo.filename, (err) => {
            if (err) {
                console.error(`Server HTTP: Lỗi khi tải xuống file ${fileInfo.filename} (ID: ${fileId}):`, err);
                // Kiểm tra xem lỗi có phải do file đã bị xóa không
                if (err.code === 'ENOENT') {
                    res.status(404).send('File không tìm thấy trên server (có thể đã bị xóa).');
                } else {
                    res.status(500).send('Lỗi khi tải xuống file.');
                }
            } else {
                console.log(`Server HTTP: Đã tải xuống thành công file ${fileInfo.filename} (ID: ${fileId}).`);
            }
        });
    } else {
        console.error(`Server HTTP: Lỗi bảo mật hoặc file không tồn tại trên đĩa: ${filePath}`);
        res.status(404).send('File không tìm thấy hoặc đường dẫn không hợp lệ.');
    }
});


server.listen(PORT, () => {
    console.log(`Server: Máy chủ ĐANG CHẠY trên http://localhost:${PORT}`);
    console.log('Server: Chờ kết nối Socket.IO từ clients...');
});

// Xử lý các lỗi không bắt được (uncaught exceptions)
process.on('uncaughtException', (err) => {
    console.error('Server: LỖI NGOẠI LỆ CHƯA ĐƯỢC XỬ LÝ:', err);
    // Có thể thực hiện các hành động dọn dẹp ở đây trước khi thoát
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Server: LỖI PROMISE CHƯA ĐƯỢC XỬ LÝ:', reason);
    // Có thể thực hiện các hành động dọn dẹp ở đây trước khi thoát
    process.exit(1);
});