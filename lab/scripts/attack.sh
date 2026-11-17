#!/usr/bin/env bash
# Gửi cùng bộ payload tới DVWA trực tiếp (không WAF) và qua WAF, so sánh kết quả,
# rồi trích audit log ModSecurity làm bằng chứng.
# Chỉ dùng trong lab cô lập (127.0.0.1). Cần: docker compose, curl, jq.
set -euo pipefail
CASES_FILE=${1:+$(realpath "$1")}   # tuỳ chọn: bộ case khác, vd. cases/bypass.txt
cd "$(dirname "$0")/.."

DIRECT=http://localhost:${DVWA_PORT:-8081}
WAF=http://localhost:${WAF_PORT:-8080}
OUT=evidence/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

token() { sed -n "s/.*name='user_token' value='\([0-9a-f]*\)'.*/\1/p" | head -1; }

# Tạo/reset CSDL DVWA (qua cổng trực tiếp để WAF không can thiệp vào bước cài đặt).
setup_db() {
  local jar=$OUT/setup.jar t
  t=$(curl -sf -c "$jar" -b "$jar" "$DIRECT/setup.php" | token)
  curl -sf -o /dev/null -c "$jar" -b "$jar" \
    --data-urlencode "create_db=Create / Reset Database" --data-urlencode "user_token=$t" \
    "$DIRECT/setup.php"
}

# Đăng nhập admin/password, lưu cookie phiên vào $2.
login() {
  local base=$1 jar=$2 t
  t=$(curl -sf -c "$jar" -b "$jar" "$base/login.php" | token)
  curl -s -o /dev/null -c "$jar" -b "$jar" \
    -d "username=admin&password=password&Login=Login&user_token=$t" "$base/login.php"
  curl -s -o /dev/null -c "$jar" -b "$jar" "$base/index.php"
  if ! curl -s -b "$jar" "$base/index.php" | grep -q "Logout"; then
    echo "Đăng nhập thất bại tại $base" >&2; exit 1
  fi
}

# Tên | phương thức | đường dẫn | dữ liệu POST | dấu hiệu khai thác thành công (regex trên body)
CASES=(
  "benign|GET|/vulnerabilities/sqli/?id=1&Submit=Submit||First name: admin"
  "sqli|GET|/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit||Surname: Brown"
  "xss|GET|/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E||<script>alert\(1\)</script>"
  "lfi|GET|/vulnerabilities/fi/?page=../../../../../../etc/passwd||root:x:0:0"
  "cmdi|POST|/vulnerabilities/exec/|ip=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd&Submit=Submit|root:x:0:0"
)
if [[ -n $CASES_FILE ]]; then mapfile -t CASES < <(grep -Ev '^[[:space:]]*(#|$)' "$CASES_FILE"); fi

# Gửi một case, in "HTTP <mã> exploit=YES|NO" (case benign*: page=OK|BROKEN).
run_case() {
  local base=$1 jar=$2 name=$3 method=$4 path=$5 data=$6 marker=$7 tag=$8 code
  local body=$OUT/$tag-$name.html
  if [[ $method == POST ]]; then
    code=$(curl -s -o "$body" -w '%{http_code}' -b "$jar" -H "X-Demo-Case: $name" --data "$data" "$base$path")
  else
    code=$(curl -s -o "$body" -w '%{http_code}' -b "$jar" -H "X-Demo-Case: $name" "$base$path")
  fi
  local ok=NO; grep -Eq "$marker" "$body" && ok=YES
  if [[ $name == benign* ]]; then
    [[ $ok == YES ]] && echo "HTTP $code page=OK" || echo "HTTP $code page=BROKEN"
  else
    echo "HTTP $code exploit=$ok"
  fi
}

echo "[*] Reset CSDL DVWA"; setup_db
echo "[*] Đăng nhập DVWA (trực tiếp và qua WAF)"
login "$DIRECT" "$OUT/direct.jar"
login "$WAF" "$OUT/waf.jar"

{
  printf '%-13s | %-22s | %-22s\n' "Case" "Direct (no WAF)" "Via WAF"
  printf -- '--------------+------------------------+------------------------\n'
  for c in "${CASES[@]}"; do
    IFS='|' read -r name method path data marker <<<"$c"
    d=$(run_case "$DIRECT" "$OUT/direct.jar" "$name" "$method" "$path" "$data" "$marker" direct)
    w=$(run_case "$WAF" "$OUT/waf.jar" "$name" "$method" "$path" "$data" "$marker" waf)
    printf '%-13s | %-22s | %-22s\n' "$name" "$d" "$w"
  done
} | tee "$OUT/summary.txt"

# Audit log: ModSecurity ghi JSON ra stdout của container waf.
sleep 1
docker compose logs --no-log-prefix --since "$SINCE" waf 2>/dev/null \
  | grep '^{"transaction"' > "$OUT/audit.json" || true

echo
echo "[*] Luật CRS đã khớp theo từng case (audit log):" | tee -a "$OUT/summary.txt"
jq -r '
  .transaction as $t
  | ($t.request.headers | to_entries[] | select(.key|ascii_downcase=="x-demo-case") | .value) as $case
  | "\($case)\tHTTP \($t.response.http_code)\t" +
    ([$t.messages[]? | .details.ruleId] | unique | join(","))
' "$OUT/audit.json" | sort -u | tee -a "$OUT/summary.txt"

rm -f "$OUT"/*.jar
echo
echo "[*] Bằng chứng lưu tại lab/$OUT (summary.txt, audit.json, body từng phản hồi)"
