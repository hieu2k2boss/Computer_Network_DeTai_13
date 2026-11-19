#!/usr/bin/env bash
# Đo chi phí hiệu năng của WAF bằng ab (ApacheBench, chạy trong container httpd).
# So sánh: DVWA trực tiếp, qua nginx với ModSecurity tắt (Off), bật ở PL1 và PL4.
# Lab phải đang chạy (docker compose up -d). Script khởi động lại container waf, cuối cùng trả về PL1.
set -euo pipefail
cd "$(dirname "$0")/.."

N=${N:-2000}; C=${C:-10}; ROUNDS=${ROUNDS:-5}
DIRECT=http://localhost:${DVWA_PORT:-8081}
WAF=http://localhost:${WAF_PORT:-8080}
# Tệp tĩnh kèm tham số: WAF vẫn kiểm tra đủ request, nhưng loại được nhiễu từ PHP/CSDL
# (các trang PHP của DVWA khoá file session, request cùng phiên bị xếp hàng).
URLPATH="/dvwa/css/main.css?id=2&page=1&Submit=Submit"
AB_IMAGE=httpd:2.4-alpine@sha256:32bd0639bcc4917ef1fd9363a1d9dd2dd9c498565118b062a10d51e43a5c3a24
OUT=evidence/bench-$(date +%Y%m%d-%H%M%S).txt
mkdir -p evidence

restart_waf() {  # $1 = rule engine, $2 = paranoia
  MODSEC_RULE_ENGINE=$1 BLOCKING_PARANOIA=$2 docker compose up -d waf >/dev/null 2>&1
  until curl -sf -o /dev/null "$WAF/login.php"; do sleep 1; done
}

bench() {  # $1 = nhãn, $2 = base URL
  local r
  docker run --rm --network host "$AB_IMAGE" ab -q -n 300 -c "$C" -H "Accept: text/css" "$2$URLPATH" >/dev/null   # khởi động (warm-up), bỏ kết quả
  r=$(docker run --rm --network host "$AB_IMAGE" ab -q -n "$N" -c "$C" -H "Accept: text/css" "$2$URLPATH")
  printf '%-14s %8s req/s  mean %6s ms  p50 %4s ms  p95 %4s ms  non-2xx %s\n' "$1" \
    "$(awk '/^Requests per second/{print $4}' <<<"$r")" \
    "$(awk '/^Time per request/{print $4; exit}' <<<"$r")" \
    "$(awk '$1=="50%"{print $2}' <<<"$r")" \
    "$(awk '$1=="95%"{print $2}' <<<"$r")" \
    "$(awk '/^Non-2xx/{print $3}' <<<"$r" | grep . || echo 0)"
}

{
  echo "# ab -n $N -c $C, GET $URLPATH, $ROUNDS vòng xen kẽ"
  for r in $(seq "$ROUNDS"); do
    bench "direct" "$DIRECT"
    restart_waf Off 1;  bench "waf-off" "$WAF"
    restart_waf On 1;   bench "waf-on-pl1" "$WAF"
    restart_waf On 4;   bench "waf-on-pl4" "$WAF"
  done
} | tee "$OUT"
echo "# Trung vị (req/s, mean ms):" | tee -a "$OUT"
for k in direct waf-off waf-on-pl1 waf-on-pl4; do
  grep "^$k " "$OUT" | awk '{print $2, $5}' | sort -n | awk -v k="$k" \
    '{a[NR]=$1; b[NR]=$2} END {m=int((NR+1)/2); printf "%-14s %8s req/s  mean %6s ms\n", k, a[m], b[m]}'
done | tee -a "$OUT"
restart_waf On 1
echo "[*] Kết quả lưu tại lab/$OUT"
