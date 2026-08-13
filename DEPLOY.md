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

## 7. Khởi động website

```bash
sudo docker compose pull
sudo docker compose build
sudo docker compose up -d
sudo docker compose ps
```

## 8. Kiểm tra log

```bash
sudo docker compose logs --tail=100 caddy api postgres dashboard
```

## 9. Mở wizard

```text
https://ops.example.com
```

## 10. Nhập kết nối PostgreSQL

```text
Máy chủ: postgres
Cổng: 5432
SSL: Ưu tiên SSL
Tên database: tramops
Tài khoản database: tramops
Mật khẩu database: giá trị POSTGRES_PASSWORD ở bước 5
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

## 14. Cập nhật phiên bản sau này

```bash
cd dashboard-mgmt
git pull --ff-only
sudo docker compose build
sudo docker compose up -d
sudo docker compose ps
```
