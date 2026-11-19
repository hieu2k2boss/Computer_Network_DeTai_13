# Đề tài 13 — ModSecurity/Coraza + OWASP CRS (Mạng thế hệ mới)

## Build báo cáo

Cần TeX Live (Linux) hoặc MiKTeX (Windows) có `latexmk` + `biber`.

```sh
cd report
latexmk          # ra report/build/main.pdf
latexmk -c       # dọn file tạm
```

- Sửa tên thành viên / giảng viên / lớp: đầu `report/main.tex`.
- Nội dung từng chương: `report/chapters/*.tex`. Ảnh: `report/figures/`.
- `\todo{...}` hiện chữ đỏ — phải xóa hết trước khi nộp: `grep -rn '\\todo' report/chapters`.

## Lab (yêu cầu 3, 4, 8)

Nginx + ModSecurity v3 + OWASP CRS 4.30.0 đứng trước DVWA, chạy bằng Docker Compose. Image được ghim theo digest.

| Địa chỉ | Đường đi |
| --- | --- |
| http://localhost:8080 | WAF → DVWA (có WAF) |
| http://localhost:8081 | DVWA trực tiếp (không WAF, để đối chứng) |

Cô lập: cổng chỉ bind `127.0.0.1`; CSDL nằm trong mạng `internal`, không ra được Internet.

```sh
cd lab
docker compose up -d          # lần đầu chờ ~20s cho MariaDB khởi động
./scripts/attack.sh           # reset DB, đăng nhập, chạy SQLi/XSS/LFI/CMDi cả 2 đường, trích audit log
docker compose logs waf       # audit log JSON của ModSecurity
docker compose down
```

Đăng nhập DVWA bằng trình duyệt: `admin` / `password`. Trước lần đầu dùng trình duyệt, chạy `attack.sh` một lần hoặc vào `/setup.php` bấm "Create / Reset Database".

Log WAF về Loki/Grafana (yêu cầu 7): `docker compose --profile siem up -d`, mở http://localhost:3000, dashboard **WAF - ModSecurity + CRS**.

Các bước demo (cho video), bộ case biến thể / hợp lệ và đo hiệu năng: [`lab/DEMO.md`](lab/DEMO.md).

Bằng chứng mỗi lần chạy nằm ở `lab/evidence/<thời-gian>/`: `summary.txt`, `audit.json`, và body từng phản hồi.

Biến môi trường (đặt trước lệnh hoặc trong `lab/.env`):

| Biến | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `MODSEC_RULE_ENGINE` | `On` | `On` chặn, `DetectionOnly` chỉ ghi log |
| `BLOCKING_PARANOIA` | `1` | Paranoia level 1–4 |
| `ANOMALY_INBOUND` / `ANOMALY_OUTBOUND` | `5` / `4` | Ngưỡng điểm chặn |
| `EXCLUSION_FILE` | `./rules/none.conf` | File luật loại trừ nạp sau CRS, ví dụ `./rules/dvwa-exclusions.conf` |
| `WAF_PORT` / `DVWA_PORT` | `8080` / `8081` | Đổi nếu cổng đã bị chiếm |
| `GRAFANA_PORT` | `3000` | Cổng Grafana (profile `siem`) |

Ví dụ: `MODSEC_RULE_ENGINE=DetectionOnly docker compose up -d waf`.
