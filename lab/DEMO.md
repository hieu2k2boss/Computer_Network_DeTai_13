# Các bước demo (yêu cầu 4)

Dùng cho video demo và để chạy lại kết quả trong Chương 5. Chỉ chạy trong lab: mọi cổng bind `127.0.0.1`.

Trên máy có cổng 8080/8081 đã bị chiếm, đặt `export WAF_PORT=28080 DVWA_PORT=28081` trước mọi lệnh và thay cổng trong URL tương ứng.

## 0. Chuẩn bị

```sh
cd lab
docker compose up -d
docker compose ps            # db phải "healthy", waf và dvwa "running"
```

Mở 2 tab trình duyệt:

- Tab A, **không WAF**: http://localhost:8081
- Tab B, **có WAF**: http://localhost:8080

Ở tab A vào `/setup.php`, bấm **Create / Reset Database**. Đăng nhập `admin` / `password` ở cả hai tab. Mức bảo mật mặc định của DVWA là `low`.

Mở thêm một terminal để xem audit log trực tiếp:

```sh
docker compose logs -f --no-log-prefix waf | grep --line-buffered '^{"transaction"' \
  | jq -c '.transaction | {uri: .request.uri, code: .response.http_code, rules: [.messages[].details.ruleId]}'
```

## 1. Gửi từng payload ở tab A rồi tab B

Kết quả mong đợi: tab A khai thác được, tab B trả `403 Forbidden` và terminal hiện các luật đã khớp.

| # | Trang DVWA | Nhập vào ô | Tab A (không WAF) | Tab B (WAF), luật |
| --- | --- | --- | --- | --- |
| 1 | SQL Injection | `1' OR '1'='1` | 5 người dùng hiện ra | 403, 942100 + 949110 |
| 2 | XSS (Reflected) | `<script>alert(1)</script>` | Hộp thoại `alert` bật lên | 403, 941100/110/160/390 + 949110 |
| 3 | File Inclusion | Sửa URL thành `?page=../../../../../../etc/passwd` | Nội dung `/etc/passwd` ở đầu trang | 403, 930100/110/120, 932160 + 949110 |
| 4 | Command Injection | `127.0.0.1;cat /etc/passwd` | Nội dung `/etc/passwd` sau kết quả ping | 403, 930120, 932160 + 949110 |

Trước khi gửi payload, nhập một giá trị hợp lệ như `1` ở trang SQL Injection trên tab B để cho thấy WAF không chặn yêu cầu bình thường.

## 2. DetectionOnly: WAF chỉ ghi log, không chặn

```sh
MODSEC_RULE_ENGINE=DetectionOnly docker compose up -d waf
```

Đăng nhập lại ở tab B, vì container waf mới đã thay cho container cũ. Lặp lại bước 1: tab B giờ cũng khai thác được (200), nhưng terminal audit log vẫn hiện đủ các luật. Riêng File Inclusion còn có thêm 953100 và 959100, là các luật kiểm tra phản hồi.

Trả về chế độ chặn:

```sh
docker compose up -d waf
```

## 3. (Tuỳ chọn) Paranoia level: bỏ sót, chặn nhầm và tinh chỉnh

- **PL1:** ở trang Command Injection trên tab B, nhập `127.0.0.1;id`. Lệnh chạy được (`uid=33(www-data)`) và không luật nào khớp.
- **PL3:** chạy `BLOCKING_PARANOIA=3 docker compose up -d waf` rồi đăng nhập lại.
  - Payload trên giờ bị chặn bởi luật 932350.
  - Trang SQL Injection với `1` cũng bị 403: luật 932350 coi tên tham số `id` là lệnh Unix, tức là chặn nhầm.
- **Tinh chỉnh:** chạy `EXCLUSION_FILE=./rules/dvwa-exclusions.conf BLOCKING_PARANOIA=3 docker compose up -d waf`.
  - Luật loại trừ trong file này chỉ có 1 dòng.
  - `?id=1` qua được, còn `127.0.0.1;id` vẫn bị chặn.
- Trả lại PL1 bằng `docker compose up -d waf`.

## 4. Chạy tự động và lưu bằng chứng

```sh
./scripts/attack.sh                       # 4 kịch bản chính (Chương 5)
./scripts/attack.sh cases/bypass.txt      # 15 biến thể payload (Chương 7, Bảng 7.1)
./scripts/attack.sh cases/benign.txt      # 10 thao tác hợp lệ, đo chặn nhầm (Bảng 7.2)
./scripts/bench.sh                        # đo hiệu năng: trực tiếp / Off / PL1 / PL4 (Bảng 7.3), mất ~3 phút
```

Đổi chế độ hoặc mức trước khi chạy, ví dụ:

```sh
MODSEC_RULE_ENGINE=DetectionOnly docker compose up -d waf
BLOCKING_PARANOIA=3 EXCLUSION_FILE=./rules/dvwa-exclusions.conf docker compose up -d waf
```

Mỗi lần chạy `attack.sh` tạo `evidence/<thời-gian>/` gồm `summary.txt`, `audit.json` và body của từng phản hồi. Thư mục này không được đưa vào Git.

Kết quả dùng trong báo cáo (chạy ngày 17/11/2026) được giữ lại trong Git:

| Thư mục | Nội dung |
| --- | --- |
| `evidence/blocking/`, `evidence/detectiononly/` | Chương 5 |
| `evidence/blocking-pl3-excl/` | 4 kịch bản ở PL3 + luật loại trừ |
| `evidence/bypass-pl1/`, `evidence/bypass-pl3-excl/` | Bảng 7.1 |
| `evidence/benign-pl{1,2,3,4}/`, `evidence/benign-pl{3,4}-excl/` | Bảng 7.2 |
| `evidence/bench.txt` | Bảng 7.3 |

## 5. Dọn dẹp

```sh
docker compose down -v
```
