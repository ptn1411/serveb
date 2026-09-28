# namsv

> Ứng dụng desktop làm **cầu nối file** trong mạng LAN — chạy ngầm ở khay hệ thống, có nút Start/Stop và tự khởi động cùng Windows.

Chọn một thư mục trên máy, bật server, rồi bất kỳ thiết bị nào cùng mạng (điện thoại, laptop khác…) mở địa chỉ LAN để **duyệt, xem và tải file** qua một giao diện web tối giản, đẹp. Toàn bộ server viết bằng **Rust (axum)**, đóng gói trong **Tauri v2** — 1 file `.exe` nhẹ, không cần cài Node.

## Tính năng

- 🖥️ **Icon khay hệ thống** — menu Bật/Tắt server, mở trình duyệt, thoát
- ▶️ **Bảng điều khiển** — chọn thư mục, đổi cổng, xem địa chỉ LAN, nút Start/Stop
- 🚀 **Tự khởi động cùng Windows** — chạy ngầm ở khay khi bật máy
- 🌙 **UI trình duyệt** — duyệt thư mục, tìm kiếm, lọc theo loại file, tải xuống
- 🎬 **Xem trực tiếp** — hỗ trợ HTTP range nên video stream/tua được ngay trong trình duyệt
- 📂 **Nhiều thư mục công khai** — thêm thư mục ở tab *Công khai*; điện thoại chọn qua lại ngay trên đầu trang. Mỗi thư mục (kể cả thư mục chính) có 3 mức quyền: *Chỉ xem* · *Tải lên* (thêm file, tạo thư mục) · *Toàn quyền* (thêm đổi tên, xóa). Áp dụng ngay, không cần khởi động lại server
- ✏️ **Quản lý file từ điện thoại** — nút ⋯ trên mỗi dòng: xem, tải về, chia sẻ, đổi tên, xóa. Xóa là **chuyển vào Thùng rác Windows** nên khôi phục được
- 🗜️ **Tải cả thư mục thành ZIP** — cho thư mục đang xem, từng thư mục con, và cả người nhận link chia sẻ thư mục. ZIP được stream ngay khi đọc file (không tạo file tạm, không giới hạn dung lượng), không nén (ảnh/video giữ nguyên, tải nhanh), giữ tên tiếng Việt và ngày sửa file
- 🖼️ **Xem ảnh dạng lưới** — ảnh thu nhỏ do server tạo (~10–30 KB thay vì cả MB, tự xoay theo EXIF như ảnh iPhone, lưu cache trong thư mục cache của app, tối đa 300 MB). Tự chuyển sang lưới khi thư mục chủ yếu là ảnh; bấm ảnh mở ngay bản thu nhỏ rồi thay bằng ảnh gốc. Hỗ trợ JPG/PNG/GIF/WebP/BMP (HEIC chỉ hiện biểu tượng; Safari trên iPhone vẫn xem được ảnh gốc)
- ↕️ **Sắp xếp** theo tên (số thông minh: IMG_2 trước IMG_10), ngày sửa, dung lượng — nhớ lựa chọn trên từng máy
- ▦ **Mã QR** — QR cho địa chỉ LAN (iPhone quét bằng Camera là vào) và cho từng link chia sẻ
- 🔑 **Giữ đăng nhập 30 ngày** — mỗi thiết bị một phiên, không bị đăng xuất khi đổi thư mục/cổng hay tắt-bật server; có nút *Đăng xuất* trên web và danh sách *Thiết bị đã đăng nhập* trong app để đăng xuất từng máy. Đổi mã PIN sẽ đăng xuất tất cả
- 🔗 **Link chia sẻ tạm thời** — cho 1 file hoặc 1 thư mục, có thời hạn (1 giờ → 30 ngày) và mật khẩu 4 số. Người nhận chỉ xem & tải về. Nhập sai 5 lần thì link tự khóa (mở khóa lại được trong app)
- 🚫 **Chống dò mã PIN** — sai 5 lần trên một thiết bị thì thiết bị đó bị khóa 5 phút; sai tổng cộng 20 lần (mọi thiết bị) thì khóa đăng nhập tất cả 15 phút; mỗi lần khóa lại tăng gấp đôi (tối đa 24 giờ). Khi đang khóa, nhập đúng PIN cũng không vào được. Người đã đăng nhập vẫn dùng bình thường; mở khóa được ngay trong app
- 📜 **Nhật ký** — ghi lại đăng nhập, tải lên, tạo/xóa/mở link, tải qua link (kèm IP)
- 🗄️ **Cơ sở dữ liệu SQLite** — thư mục công khai, link và nhật ký lưu trong `namsv.db` (nhúng sẵn, không cần cài gì)
- 🔒 **Chống path traversal** — chỉ phục vụ trong đúng thư mục đã chọn
- 🪶 **Nhẹ** — dùng WebView2 sẵn có của Windows, không nhúng Chromium

## Cấu trúc dự án

```
namsv/
├── ui/
│   └── index.html          # Bảng điều khiển (giao diện cửa sổ Tauri)
├── src-tauri/
│   ├── assets/
│   │   └── browser.html     # UI trình duyệt file (server nhúng & phục vụ)
│   ├── icons/               # Icon app (sinh bằng `tauri icon`)
│   ├── src/
│   │   ├── main.rs          # Tray, menu, commands, autostart, config
│   │   ├── db.rs            # SQLite: thư mục công khai, link chia sẻ, nhật ký
│   │   └── server.rs        # File server bằng axum (list API, tải file, link chia sẻ)
│   ├── Cargo.toml
│   ├── build.rs
│   └── tauri.conf.json
└── package.json             # Script tiện lợi (tuỳ chọn)
```

## Yêu cầu

- [Rust](https://rustup.rs/) (toolchain MSVC trên Windows)
- WebView2 (đã có sẵn trên Windows 10/11)
- Tauri CLI: `cargo install tauri-cli` *hoặc* `npm i` (đã khai báo trong `devDependencies`)

## Phát triển & đóng gói

```bash
# Chạy thử (hot-reload cửa sổ điều khiển)
cargo tauri dev

# Đóng gói ra installer .exe (NSIS)
cargo tauri build
```

Installer nằm ở `src-tauri/target/release/bundle/nsis/`.

## Cách hoạt động

Server Rust mở HTTP trên `0.0.0.0:<port>`. `root=0` là thư mục chính, các số khác là thư mục công khai trong database.

| Tuyến | Chức năng |
|-------|-----------|
| `/` | Trả về UI trình duyệt file (nhúng sẵn) |
| `/__api/roots` | Danh sách thư mục điện thoại được chọn |
| `/__api/list?root=0&path=/` | API JSON liệt kê thư mục |
| `/__f/<root>/<đường dẫn>` | Tải/stream file (hỗ trợ range) |
| `PUT /__api/upload?root=&path=&name=` | Tải file lên (quyền *Tải lên* trở lên) |
| `POST /__api/mkdir` · `/__api/rename` · `/__api/delete` | Tạo thư mục (*Tải lên*) · đổi tên, xóa vào Thùng rác (*Toàn quyền*) |
| `POST /__api/logout` | Đăng xuất thiết bị hiện tại |
| `/__api/qr?text=` | Ảnh QR (SVG) |
| `/__api/zip?root=&path=` · `/s/<mã>/zip?path=` | Tải thư mục thành ZIP (stream) |
| `/__thumb/<root>/<đường dẫn>` · `/s/<mã>/thumb/<đường dẫn>` | Ảnh thu nhỏ JPEG (cache) |
| `/__api/links` | Tạo (`POST`) / liệt kê (`GET`) / xóa (`DELETE /__api/links/<id>`) link chia sẻ |
| `/s/<mã>` | Trang link chia sẻ — **không** cần PIN chung, chỉ cần mật khẩu riêng của link |
| `/*` | Tải file trong thư mục chính (giữ tương thích link cũ) |

Mọi tuyến trừ `/s/…` đều nằm sau mã PIN đăng nhập (nếu bật). Cookie của link chia sẻ chỉ có hiệu lực trong đúng link đó.

Cấu hình (thư mục, cổng, tuỳ chọn) lưu trong `config.json`; thư mục công khai, link và nhật ký lưu trong `namsv.db` — cả hai nằm trong thư mục config của app (`%APPDATA%\com.ptn1411.namsv\`). Link hết hạn quá 7 ngày được tự dọn khi mở app; nhật ký giữ 2000 dòng gần nhất.

```bash
# Chạy test (database + các tuyến HTTP)
cd src-tauri && cargo test

# Kiểm tra thật việc chuyển vào Thùng rác (có đụng tới Thùng rác của máy, tự dọn lại)
cd src-tauri && cargo test trash_really_recycles -- --ignored
```

## License

MIT
