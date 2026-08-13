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
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
SETUP_TOKEN=$(openssl rand -hex 32)
GUACAMOLE_JSON_SECRET=$(openssl rand -hex 16)
sed -i "s|^OPS_DOMAIN=.*|OPS_DOMAIN=ops.example.com|" .env
sed -i "s|^ACME_EMAIL=.*|ACME_EMAIL=admin@example.com|" .env
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$POSTGRES_PASSWORD|" .env
sed -i "s|^SETUP_TOKEN=.*|SETUP_TOKEN=$SETUP_TOKEN|" .env
sed -i "s|^GUACAMOLE_JSON_SECRET=.*|GUACAMOLE_JSON_SECRET=$GUACAMOLE_JSON_SECRET|" .env
chmod 600 .env
printf 'SETUP_TOKEN=%s\nPOSTGRES_PASSWORD=%s\n' "$SETUP_TOKEN" "$POSTGRES_PASSWORD"
```

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
sudo docker compose -f compose.yaml -f compose.test.yaml logs --tail=100 caddy api postgres dashboard
```

## 8B. Kiểm tra log bản PostgreSQL bên ngoài

```bash
sudo docker compose -f compose.yaml -f compose.external.yaml logs --tail=100 caddy api dashboard
```

## 9. Mở wizard

```text
https://ops.example.com
```

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

## 14A. Cập nhật bản test

```bash
cd dashboard-mgmt
git pull --ff-only
sudo docker compose -f compose.yaml -f compose.test.yaml build
sudo docker compose -f compose.yaml -f compose.test.yaml up -d
sudo docker compose -f compose.yaml -f compose.test.yaml ps
```

## 14B. Cập nhật bản PostgreSQL bên ngoài

```bash
cd dashboard-mgmt
git pull --ff-only
sudo docker compose -f compose.yaml -f compose.external.yaml build
sudo docker compose -f compose.yaml -f compose.external.yaml up -d
sudo docker compose -f compose.yaml -f compose.external.yaml ps
```
