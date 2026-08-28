# Chạy website trên Ubuntu 24.04

## 1. Trỏ DNS

```text
ops.example.com -> PUBLIC_IP_CUA_SERVER
```

## 2. Mở cổng

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 9443/tcp
sudo ufw enable
```

## 3. Cài Docker

```bash
sudo apt update
sudo apt install -y ca-certificates curl git openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

## 4. Tải source code

```bash
git clone https://github.com/anhnn1639/dashboard-mgmt.git
cd dashboard-mgmt
git switch main
```

## 5. Tạo file cấu hình

```bash
cp .env.example .env
POSTGRES_PASSWORD=$(openssl rand -hex 32)
SETUP_TOKEN=$(openssl rand -hex 32)
GUACAMOLE_JSON_SECRET=$(openssl rand -hex 16)
sed -i "s|^OPS_DOMAIN=.*|OPS_DOMAIN=ops.example.com|" .env
sed -i "s|^WEB_BIND_PORT=.*|WEB_BIND_PORT=3000|" .env
sed -i "s|^WEB_TLS_TRUST=.*|WEB_TLS_TRUST=system|" .env
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" .env
sed -i "s|^SETUP_TOKEN=.*|SETUP_TOKEN=$SETUP_TOKEN|" .env
sed -i "s|^GUACAMOLE_JSON_SECRET=.*|GUACAMOLE_JSON_SECRET=$GUACAMOLE_JSON_SECRET|" .env
chmod 600 .env
printf 'SETUP_TOKEN=%s\nPOSTGRES_PASSWORD=%s\n' "$SETUP_TOKEN" "$POSTGRES_PASSWORD"
```

`.env` chứa secret nên bị Git ignore và không bao giờ được pull/ghi đè. Với máy đã
cài từ phiên bản cũ, sau khi pull hãy chạy `deploy/configure-nginx.sh` ở bước 8C;
script sẽ backup rồi upsert `OPS_DOMAIN`, `WEB_BIND_PORT` và `WEB_TLS_TRUST` mà
không thay đổi password/token hiện hữu.

## 6. Tạo PKI

```bash
bash deploy/generate-pki.sh
chmod 600 deploy/pki/agent-ca.key
```

## 7A. Chạy test với PostgreSQL trong Docker

```bash
sudo docker compose -f compose.yaml -f compose.test.yaml pull
sudo docker compose -f compose.yaml -f compose.test.yaml build
sudo docker compose -f compose.yaml -f compose.test.yaml up -d
sudo docker compose -f compose.yaml -f compose.test.yaml ps
```

## 7B. Chạy với PostgreSQL bên ngoài

```bash
nano .env
```

```text
EXTERNAL_DATABASE_URL=postgresql+psycopg://USERNAME:PASSWORD@DB_HOST:5432/DB_NAME?sslmode=require
```

```bash
sudo docker compose -f compose.yaml -f compose.external.yaml pull
sudo docker compose -f compose.yaml -f compose.external.yaml build
sudo docker compose -f compose.yaml -f compose.external.yaml up -d
sudo docker compose -f compose.yaml -f compose.external.yaml ps
```

## 8A. Kiểm tra log bản test

```bash
sudo docker compose -f compose.yaml -f compose.test.yaml logs --tail=100 caddy api clamav postgres dashboard
```

## 8B. Kiểm tra log bản PostgreSQL bên ngoài

```bash
sudo docker compose -f compose.yaml -f compose.external.yaml logs --tail=100 caddy api clamav dashboard
```

## 8C. Kết nối Nginx với Caddy trên port 3000

Compose không còn chiếm host port `80/443`. Web Caddy chỉ được publish tại
`127.0.0.1:3000`; agent mTLS vẫn dùng public `9443`.

Chờ `caddy-ca-export` đồng bộ CA công khai dùng cho cả API và Nginx xác minh upstream:

```bash
sudo docker compose -f compose.yaml -f compose.test.yaml ps caddy-ca-export api
sudo docker compose -f compose.yaml -f compose.test.yaml logs --tail=50 caddy-ca-export
test -s deploy/pki/public/server-ca.crt
sudo docker compose -f compose.yaml -f compose.test.yaml exec api \
  python -c "from pathlib import Path; assert Path('/run/server-ca/server-ca.crt').stat().st_size > 0"
curl --cacert deploy/pki/public/server-ca.crt \
  --resolve ops.example.com:3000:127.0.0.1 \
  https://ops.example.com:3000/
```

`caddy-ca-export` không có network, chỉ đọc volume Caddy và chỉ xuất public root. Nếu
trang **Bộ cài Agent** báo CA chưa sẵn sàng sau khi nâng cấp, recreate đúng hai service:

```bash
sudo docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api caddy-ca-export
```

Sau khi nâng cấp từ đường dẫn CA cũ, chạy lại `deploy/configure-nginx.sh` ở dưới để
Nginx dùng `deploy/pki/public/server-ca.crt`, rồi kiểm tra `nginx -t` trước khi reload.

Script sau đồng bộ ba biến runtime vào `.env` và render toàn bộ Nginx virtual host
từ template được Git quản lý. Nó tạo bản backup của cả `.env` và Nginx config nếu
file đã tồn tại:

```bash
sudo sh deploy/configure-nginx.sh \
  ops.example.com \
  /etc/letsencrypt/live/ops.example.com/fullchain.pem \
  /etc/letsencrypt/live/ops.example.com/privkey.pem \
  /etc/nginx/sites-available/tram-ops

sudo ln -s /etc/nginx/sites-available/tram-ops /etc/nginx/sites-enabled/tram-ops
sudo docker compose -f compose.yaml -f compose.test.yaml up -d --build
sudo nginx -t
sudo systemctl reload nginx
```

Nếu certificate và private key nằm chung một PEM đã được kiểm tra bằng
`openssl pkey`, có thể truyền cùng một đường dẫn cho tham số thứ hai và thứ ba. Nếu Nginx
đã có server block khác cho cùng domain, phải disable/gộp file cũ trước khi reload.

Không dùng `proxy_ssl_verify off`. Nginx phải có certificate public được Windows
và Linux tin cậy mặc định vì `.env` đặt `WEB_TLS_TRUST=system`. Port `3000` không
được mở bằng UFW hoặc NAT ra ngoài.

## 9. Mở wizard

```text
https://ops.example.com
```

Public TLS kết thúc tại Nginx. Hop Nginx tới Caddy vẫn là HTTPS và được xác minh
bằng `deploy/pki/public/server-ca.crt`; không cần import CA Caddy vào trình duyệt.

## 10. Nhập kết nối PostgreSQL

### Bản test

```text
Máy chủ: postgres
Cổng: 5432
SSL: Ưu tiên SSL
Tên database: tramops
Tài khoản database: tramops
Mật khẩu database: giá trị POSTGRES_PASSWORD ở bước 5
```

### PostgreSQL bên ngoài

```text
Máy chủ: DB_HOST
Cổng: 5432
SSL: Bắt buộc SSL
Tên database: DB_NAME
Tài khoản database: USERNAME
Mật khẩu database: PASSWORD
```

## 11. Tạo admin local

```text
Tên đăng nhập: admin
Tên hiển thị: Platform Administrator
Mật khẩu: tối thiểu 14 ký tự
```

## 12. Nhập URL dashboard

```text
Dashboard URL: https://ops.example.com
Mã thiết lập: giá trị SETUP_TOKEN ở bước 5
```

## 13. Hoàn tất

```text
Nhấn: Kiểm tra kết nối & hoàn tất
Đăng nhập bằng tài khoản admin vừa tạo
```

## 13A. Kiểm tra bộ cài Agent theo domain thật

1. Mở dashboard bằng chính URL HTTPS production, không dùng IP hoặc alias tạm.
2. Vào **Bộ cài Agent** và xác nhận URL hiển thị khớp `OPS_DOMAIN`.
3. Tải thử một Linux `.run` và một Windows `.msi`; không đổi tên MSI.
4. Claim chỉ sống 15–60 phút và dùng một lần. Xóa file tải về sau khi máy đã enroll.
5. Windows MSI cài service `TramVanHanhAgent` kiểu `Automatic`; kiểm tra bằng:

   ```powershell
   Get-Service TramVanHanhAgent
   Get-Content "$env:ProgramData\TramVanHanh\agent.log" -Tail 100
   ```

6. MSI mặc định trong repository chưa có chữ ký publisher. Trước production, cấu hình code-signing certificate trong GitHub Actions, build lại artifact, kiểm tra `Get-AuthenticodeSignature`, thay `agent/windows/TramVanHanhAgent.msi` và rebuild container API. Không đặt private key ký mã trên dashboard.

## 14. Firewall máy được quản lý

- Agent chỉ cần outbound TCP `9443` tới hostname trong **Bộ cài Agent**; cho outbound
  `443` trong lúc bootstrap/enrollment.
- Không mở inbound cho agent.
- Đóng inbound `22/3389` từ mạng thông thường. Nếu cần break-glass, chỉ cho
  phép một bastion riêng có MFA.
- Chặn server-to-server tới `22`, `3389`, `445` và các mạng control/database.
- Không public `3310` (ClamAV), `4822` (guacd), `5432` (PostgreSQL) hoặc các
  cổng relay tạm thời của container API.

## 14A. Kiểm tra SSH qua reverse tunnel

Không mở inbound `22` từ dashboard hoặc các máy chủ khác. Agent chỉ relay tới
`127.0.0.1:22` trên chính máy Linux đích. Sau khi cập nhật control plane, rebuild
hai service có thay đổi:

```bash
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api guacamole guacd
```

Nếu dashboard báo Agent không chuẩn bị được `127.0.0.1:22`, kiểm tra trên máy đích:

```bash
sudo systemctl status ssh --no-pager      # Ubuntu 24.04
sudo systemctl status sshd --no-pager     # Oracle Linux 7/8
sudo ss -lntp | grep ':22'
sudo journalctl -u tram-agent -n 150 --no-pager
```

Luồng mới chờ stream Agent mTLS sẵn sàng rồi mới mở Guacamole, nên lỗi dịch vụ
SSH local sẽ trả về dashboard trước khi trình duyệt chuyển sang màn hình Guacamole.

## 14B. Cập nhật bản vá clipboard của phiên SSH/RDP

Guacamole 1.6.0 có race condition khi tab remote lấy lại focus: clipboard mới có thể
chưa đồng bộ xong nhưng phím hoặc chuột paste đã được gửi, khiến nội dung cũ được
dán lại. Repository đóng gói extension `tram-clipboard-sync-v3` vào image Guacamole
tùy biến. Extension gate đúng từng client instance do `ManagedClient` tạo, ép đọc mới
khi nhấn chuột phải/giữa ở capture phase và chỉ chuyển tiếp mouse input sau khi sync
browser → remote hoàn tất. `Ctrl+V`/`Shift+Insert` cũng luôn ép đọc mới. Chiều remote
về browser vẫn bị khóa.

Sau khi pull commit có thay đổi extension, phải build và recreate riêng Guacamole:

```bash
docker compose -f compose.yaml -f compose.test.yaml build --no-cache guacamole
docker compose -f compose.yaml -f compose.test.yaml up -d --force-recreate guacamole
docker compose -f compose.yaml -f compose.test.yaml logs --tail=100 guacamole
```

Log khởi động phải có extension namespace `tram-clipboard-sync-v3`. Mở **phiên mới**,
copy lần lượt hai chuỗi khác nhau ở máy quản trị rồi paste vào SSH/RDP; lần thứ hai
phải nhận đúng chuỗi mới mà không cần dán qua thanh địa chỉ. Nếu trình duyệt hỏi
quyền đọc clipboard, chọn **Cho phép** cho domain vận hành.

## 15A. Cập nhật bản test

```bash
cd dashboard-mgmt
git pull --ff-only
sudo docker compose -f compose.yaml -f compose.test.yaml build
sudo docker compose -f compose.yaml -f compose.test.yaml up -d
sudo docker compose -f compose.yaml -f compose.test.yaml ps
```

## 15B. Cập nhật bản PostgreSQL bên ngoài

```bash
cd dashboard-mgmt
git pull --ff-only
sudo docker compose -f compose.yaml -f compose.external.yaml build
sudo docker compose -f compose.yaml -f compose.external.yaml up -d
sudo docker compose -f compose.yaml -f compose.external.yaml ps
```
