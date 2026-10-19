# 🔄 No-IP Auto Renew (GitHub Actions + 2FA TOTP + Telegram Screenshot)

Giải pháp tự động kiểm tra và gia hạn tên miền miễn phí **No-IP (noip.com)** định kỳ hàng tháng hoàn toàn miễn phí trên **GitHub Actions** (hoặc **Docker**), được nâng cấp từ `moebiuss/noip-renew` (`loblab/noip-renew`).

## ✨ Tính năng nổi bật

- 🤖 **Chạy ngầm 100% trên GitHub Actions**: Không cần bật máy tính cá nhân hay thuê VPS/Server, tự động kiểm tra vào 08:00 sáng Thứ 2, 4, 6, Chủ Nhật hàng tuần (bắt dính chính xác cửa sổ $\le 7$ ngày của No-IP để bấm `Confirm`).
- 🔐 **Tự động điền mã 2FA (TOTP)**: Sinh mã OTP 6 số trực tiếp từ `NOIP_2FA_SECRET_KEY` bằng `pyotp`.
- 🌐 **Tương thích cả 2 giao diện No-IP**:
  - Giao diện mới 2025/2026 (`/dns/records` - `#zone-collection-wrapper` + fallback HTMX AJAX `/ajax/host/<id>/touch`).
  - Giao diện cổ điển (`/dynamic-dns` - bảng Host & nút `Confirm` màu xanh).
- 📸 **Chụp ảnh màn hình & Báo cáo qua Telegram**: Tự động chụp ảnh kết quả (`results.png`) và gửi kèm trạng thái từng tên miền trực tiếp về **Telegram** sau mỗi lần chạy.
- 🐳 **Hỗ trợ sẵn Docker & Docker Compose**: Có thể triển khai trên NAS Synology, Raspberry Pi, Home Server bất cứ lúc nào.

---

## 🛠️ Hướng dẫn cấu hình GitHub Secrets

Vào trang GitHub Repository: **`Settings` ➔ `Secrets and variables` ➔ `Actions` ➔ `New repository secret`** và thêm các biến sau:

| Tên Secret | Bắt buộc | Mô tả |
| :--- | :---: | :--- |
| `NOIP_USERNAME` | ✅ | Email hoặc Username đăng nhập tài khoản No-IP |
| `NOIP_PASSWORD` | ✅ | Mật khẩu tài khoản No-IP |
| `NOIP_2FA_SECRET_KEY` | ✅ | Mã khóa bí mật 2FA (chuỗi 16 ký tự Base32 khi bật 2FA trên No-IP) |
| `TELEGRAM_BOT_TOKEN` | Tùy chọn | Token của Bot Telegram (tạo qua `@BotFather`) |
| `TELEGRAM_CHAT_ID` | Tùy chọn | Chat ID nhận tin nhắn & ảnh chụp màn hình |

### 💡 Cách lấy `NOIP_2FA_SECRET_KEY` trên No-IP:
1. Đăng nhập vào [my.noip.com](https://my.noip.com/) ➔ Vào **Account** ➔ **Security** (Bảo mật).
2. Tại mục **Two-Factor Authentication (2FA)**, chọn **Enable** (hoặc tắt đi bật lại nếu trước đó chưa lưu mã Secret Key).
3. Ở bước quét mã QR, bấm vào dòng **"Can't scan the QR code?"** (hoặc nhìn bên dưới mã QR) để lấy chuỗi **Secret Key** (gồm 16 ký tự chữ và số, ví dụ: `JBSWY3DPEHPK3PXP`).
4. Lưu chuỗi này vào `NOIP_2FA_SECRET_KEY` và quét mã QR bằng Google Authenticator như bình thường để hoàn tất kích hoạt.

---

## 🚀 Cách chạy thử ngay trên GitHub Actions

1. Mở tab **Actions** trên GitHub Repository.
2. Chọn workflow **No-IP Auto Renew (2FA + Telegram)** ở cột bên trái.
3. Bấm nút **Run workflow** ➔ **Run workflow**.
4. Chờ khoảng 40–60 giây, kết quả kèm ảnh chụp màn hình trang quản trị No-IP sẽ được gửi thẳng về Telegram của bạn (đồng thời lưu trong phần **Artifacts** của phiên chạy).

---

## 🐳 Chạy bằng Docker (Tùy chọn cho NAS / Home Server)

1. Tạo file `.env` từ `.env.example`:
   ```bash
   cp .env.example .env
   ```
2. Điền thông tin vào `.env` rồi chạy:
   ```bash
   docker compose run --rm noip-renew
   ```
