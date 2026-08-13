# Trạm Vận Hành

Control plane tự host để giám sát và vận hành tập trung Windows Server và Linux. Bản hiện tại là MVP có kiến trúc triển khai thực tế, API/agent chạy được và giao diện quản trị responsive. Trước khi dùng cho production quy mô lớn, cần kiểm thử trong môi trường staging, tích hợp IdP/vault của tổ chức và thực hiện pentest.

## Những gì đã có

- Dashboard tách tự động **Windows** và **Linux**, không yêu cầu chọn thủ công khi cài agent.
- Inventory: hostname, OS/version, kiến trúc, IP, kernel, CPU, RAM, disk, uptime, số dịch vụ và bản vá chờ.
- Agent outbound cho Windows Server 2025, Ubuntu 24.04 và Oracle Linux 7/8.
- Enrollment một lần bằng token; agent tự tạo private key/CSR trên máy đích.
- Agent API riêng ở TCP `9443`, bắt buộc **mTLS** và xác minh certificate bằng CA nội bộ.
- Dashboard/API ở TCP `443` qua TLS tự động của Caddy.
- RBAC (`admin`, `operator`, `viewer`, `auditor`), đăng nhập Local/LDAP Domain, MFA TOTP bắt buộc, JWT ngắn hạn và Argon2 password hashing.
- Công việc có cấu trúc và allowlist; không có endpoint chạy shell tùy ý.
- Quy tắc “4 mắt”: người tạo không thể tự duyệt tác vụ nguy hiểm.
- Quản lý local user/group theo máy đang chọn: tạo/khóa/mở khóa/xóa/reset mật khẩu, tạo/xóa group và thêm/xóa thành viên.
- Scan/cài security updates, start/stop/restart service, xem process, firewall, journal/Event Log và reboot.
- SSH/RDP trong trình duyệt qua Apache Guacamole 1.6; native recording giữ độ phân giải nguồn, có trình phát tại tab Nhật ký kiểm toán và SSH typescript.
- Audit log liên kết hash để phát hiện chỉnh sửa/xóa/chèn sự kiện ngoài luồng.
- Docker Compose cho Ubuntu 24.04 với Postgres, API, dashboard, Caddy, Guacamole và guacd.

## Tự động phân loại Windows/Linux

Agent thu thập dấu vân tay hệ điều hành trước khi enroll:

- Windows: `platform.system()` kết hợp `Win32_OperatingSystem` qua CIM.
- Linux: `platform.system()` kết hợp `/etc/os-release`; Ubuntu có `ID=ubuntu`, Oracle Linux có `ID=ol`.

Control plane tự gán `os_family=windows|linux`; API và giao diện lọc theo giá trị đã xác minh. Nếu một agent đã enroll bỗng báo đổi family, máy bị chuyển sang `quarantined`, ghi audit `agent.os_family.changed` và không tự chuyển mục.

## Kiến trúc

```text
Trình duyệt ── TLS/443 ── Caddy ─┬─ Dashboard
                                 ├─ Control Plane API ── PostgreSQL
                                 └─ Guacamole ── guacd ── SSH/22 hoặc RDP/3389 ── Máy đích

Windows/Linux Agent ── mTLS/9443 ── Caddy ── Control Plane API
        │                                 │
        └─ private key không rời máy      └─ allowlist job + RBAC + audit
```

Agent chỉ cần kết nối outbound tới control plane. Không cần mở thêm cổng inbound cho agent. `guacd` không được publish ra host; chỉ container Guacamole truy cập được.

## Cài control plane trên Ubuntu 24.04

### 1. Chuẩn bị

- Ubuntu Server 24.04 LTS x86_64/arm64.
- Tối thiểu 4 vCPU, 8 GB RAM, 80 GB disk cho lab; production cần tính riêng dung lượng recording.
- DNS `ops.example.com` trỏ tới máy control plane.
- Mở inbound TCP `80`, `443`, `9443`. Giới hạn `9443` theo IP/VPN nếu có thể.
- Control plane/`guacd` phải route được tới IP quản trị của máy đích trên TCP `22` hoặc `3389`.
- Docker Engine và Docker Compose plugin theo tài liệu chính thức: <https://docs.docker.com/engine/install/ubuntu/>.

Docker có thể tạo rule iptables vượt qua một số rule UFW. Chỉ publish ba port trong `compose.yaml`, kiểm soát thêm bằng firewall upstream và `DOCKER-USER` chain.

### 2. Tạo cấu hình và PKI

```bash
git clone <REPOSITORY_URL> tram-van-hanh
cd tram-van-hanh
cp .env.example .env
bash deploy/generate-pki.sh
chmod 600 .env deploy/pki/agent-ca.key
```

Sửa `.env` và sinh secret ngẫu nhiên:

```bash
openssl rand -hex 32        # POSTGRES_PASSWORD
openssl rand -hex 32        # SETUP_TOKEN
openssl rand -hex 16        # GUACAMOLE_JSON_SECRET: đúng 32 ký tự hex
```

Production đặt `RECORDING_DIR=/srv/tram-ops/recordings` (hoặc mount riêng có quota). Compose tạo quyền host path cho UID/GID của Guacamole; không dùng Docker named volume nên có thể theo dõi và giới hạn dung lượng trực tiếp từ host.

Không commit `.env`, private key CA hoặc recording. Sao lưu `agent-ca.key` ngoại tuyến; mất key sẽ không cấp/renew agent certificate, lộ key phải rotate toàn bộ agent. Wizard lần đầu tự sinh `JWT_SECRET` và `JOB_SECRET_KEY`, sau đó lưu chuỗi kết nối cùng hai khóa này trong volume `api_config` có quyền hạn chế. Cần sao lưu volume này cùng PostgreSQL; mất `JOB_SECRET_KEY` sẽ làm các job đang chờ không thể giải mã.

### 3. Khởi động

```bash
# Test: PostgreSQL chạy trong Docker
docker compose -f compose.yaml -f compose.test.yaml pull
docker compose -f compose.yaml -f compose.test.yaml build
docker compose -f compose.yaml -f compose.test.yaml up -d
docker compose -f compose.yaml -f compose.test.yaml ps

# Production: PostgreSQL bên ngoài, cấu hình EXTERNAL_DATABASE_URL trong .env
docker compose -f compose.yaml -f compose.external.yaml pull
docker compose -f compose.yaml -f compose.external.yaml build
docker compose -f compose.yaml -f compose.external.yaml up -d
docker compose -f compose.yaml -f compose.external.yaml ps
```

Mở `http://ops.example.com`. Khi database chưa được cấu hình, chưa kết nối được, chưa có admin hoặc chưa có URL chuẩn, dashboard tự mở màn hình **Thiết lập lần đầu**:

1. Nhập máy chủ PostgreSQL, port, database, tài khoản, mật khẩu và chế độ SSL. Với PostgreSQL trong Compose dùng host `postgres`, port `5432` và các giá trị `POSTGRES_USER` / `POSTGRES_DB` / `POSTGRES_PASSWORD` trong `.env`.
2. Tạo tài khoản admin local đầu tiên với mật khẩu tối thiểu 14 ký tự.
3. Nhập URL chính thức của dashboard và `SETUP_TOKEN` nếu đã cấu hình.

API kiểm tra kết nối, tạo schema, admin, cấu hình hệ thống và audit event trong một luồng. Sau khi hoàn tất, wizard bị khóa và dashboard chuyển sang màn hình đăng nhập. Toàn bộ dữ liệu nghiệp vụ được lưu trong PostgreSQL; volume `api_config` chỉ giữ thông tin bootstrap và khóa mã hóa không nên lưu chung với dữ liệu đã mã hóa.

## Cài agent

### 1. Tạo enrollment token

Đăng nhập lấy access token:

```bash
ACCESS_TOKEN=$(curl -fsS http://ops.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASSWORD"}' | jq -r .access_token)
```

Token dùng một lần, hết hạn sau 24 giờ:

```bash
curl -fsS http://ops.example.com/api/v1/enrollment-tokens \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"server-batch-01","expires_hours":24,"max_uses":1}'
```

Có thể thêm `"expected_os_family":"windows"` hoặc `"linux"` để token chỉ dùng được đúng loại máy.

### 2. Ubuntu 24.04 / Oracle Linux 7, 8

Trên Ubuntu, bộ cài tự cài Python 3, `venv` và OpenSSH Server. Trên Oracle Linux 7, Python hệ thống có thể quá cũ; cài Python 3.9+ và OpenSSH Server từ repository được tổ chức phê duyệt trước khi chạy.

```bash
sudo sh agent/install-linux.sh
sudo /opt/tram-agent/venv/bin/python /opt/tram-agent/tram_agent.py \
  enroll --server http://ops.example.com --token 'tvo_ONE_TIME_TOKEN'
sudo systemctl enable --now tram-agent
sudo systemctl status tram-agent
```

Máy sẽ tự xuất hiện trong **Máy chủ Linux**. Ubuntu được nhận diện từ `ID=ubuntu`; Oracle Linux từ `ID=ol`.

### 3. Windows Server 2025

Chạy PowerShell 64-bit bằng quyền Administrator. MVP hiện cần Python 3.11+ cài trên máy; script tạo Scheduled Task chạy dưới `SYSTEM`.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\agent\install-windows.ps1 `
  -Server "http://ops.example.com" `
  -EnrollmentToken "tvo_ONE_TIME_TOKEN"
```

Máy sẽ tự xuất hiện trong **Máy chủ Windows**. Windows Server 2025 có OpenSSH Server được cài sẵn nhưng mặc định chưa bật; RDP cũng phải được bật và firewall cho phép từ IP control plane/Guacamole.

## SSH/RDP và recording

1. Chọn server trong dashboard.
2. Linux hiển thị **Mở SSH**; Windows hiển thị **Remote Desktop**.
3. Nhập credential dùng cho đúng phiên. Password được đưa vào JSON Guacamole có chữ ký HMAC-SHA256, mã hóa AES-CBC và hết hạn sau 2 phút; API không lưu password và không ghi password vào audit.
4. `guacd` ghi native graphical recording vào `RECORDING_DIR`; SSH ghi thêm typescript.
5. Vào **Nhật ký kiểm toán → Video ghi session → Xem lại** để phát trực tiếp recording gốc trong trình duyệt.

Recording gốc của Guacamole không cần re-encode, giữ nguyên dữ liệu hiển thị ở độ phân giải trình duyệt yêu cầu và thường nhỏ hơn video truyền thống. Object storage retention và legal hold vẫn là hạng mục production tiếp theo. Không bật `ignore-cert` cho RDP; triển khai certificate hợp lệ cho RDP. SSH host key được agent thu thập và pin khi có Ed25519 host key.

## LDAP Domain Login và MFA

1. Đăng nhập bằng admin Local và mở **Truy cập & Vai trò**.
2. Nhập LDAP/Active Directory host, Base DN, Bind DN, service-account password, chọn LDAPS và dán CA certificate nếu dùng enterprise/private CA.
3. Bật **Domain Login**, lưu cấu hình, sau đó dùng tab **Domain Login** ở màn hình đăng nhập.
4. Lần đầu mỗi tài khoản Local hoặc Domain đăng nhập thành công, hệ thống bắt buộc quét QR TOTP và xác minh mã 6 số trước khi cấp JWT.

Mật khẩu Bind DN và TOTP secret được mã hóa bằng `JOB_SECRET_KEY` trước khi lưu PostgreSQL. Nên dùng LDAPS có certificate được API container tin cậy và HTTPS ở production; chạy HTTP sẽ làm lộ credential trên đường truyền.

## User/group theo hệ điều hành

| Hành động | Ubuntu | Oracle Linux 7/8 | Windows Server 2025 |
|---|---|---|---|
| Tạo local user | `useradd` | `useradd` | `New-LocalUser` |
| Cấp admin | group `sudo` | group `wheel` | `Administrators` |
| Cho phép SSH/RDP | group `sshlogin` theo policy | group `sshlogin` theo policy | `OpenSSH Users` / `Remote Desktop Users` |
| Disable user | lock + expire | lock + expire | `Disable-LocalUser` |
| Enable user | unlock + clear expiry | unlock + clear expiry | `Enable-LocalUser` |
| Reset password | `chpasswd` | `chpasswd` | `Set-LocalUser` |
| Xóa user/group | `userdel` / `groupdel` | `userdel` / `groupdel` | `Remove-LocalUser` / `Remove-LocalGroup` |
| Tạo group | `groupadd` | `groupadd` | `New-LocalGroup` |
| Firewall | UFW allow/deny/delete | chỉ đọc ở bản hiện tại | `New/Remove-NetFirewallRule` |
| Mở rộng storage | `lvextend --resizefs` | `lvextend --resizefs` | `Resize-Partition` tới `SizeMax` |

Tác vụ đặc quyền luôn vào `pending_approval`. Một admin khác phải gọi endpoint approve hoặc dùng màn hình phê duyệt khi được bổ sung.

## API tác vụ allowlist

`inventory.collect`, `service.*`, `user.create|disable|enable|delete|password.reset`, `group.create|delete`, `user.add_group`, `group.remove_user`, `patch.*`, `logs.read`, `process.list`, `firewall.list|rule.add|rule.remove`, `storage.list|extend`, `network.list`, `system.reboot`.

Không có `command.run`, `powershell.run` hoặc `shell.run`. Tham số user/group/service được validate bằng allowlist ký tự và mọi subprocess đều chạy không qua shell. Password/secret trong job được mã hóa bằng Fernet ở tầng ứng dụng và chỉ giải mã khi dispatch qua mTLS. Khi cần xử lý ngoài danh sách, dùng SSH/RDP có recording.

## Bảo mật và vận hành production

- Đặt dashboard sau VPN/Zero Trust; hạn chế `443/9443` theo mạng quản trị.
- Tích hợp OIDC/SAML nếu cần SSO ngoài LDAP; MFA TOTP và Local/Domain Login đã có sẵn.
- Tích hợp Vault/1Password/Bitwarden/Windows LAPS cho credential; không lưu secret trong job parameters.
- Tách CA offline hoặc tích hợp enterprise PKI; bổ sung CRL/OCSP và rotation tự động trước hạn 90 ngày.
- Mã hóa disk/volume Postgres và recording; đẩy recording sang immutable object storage.
- Backup Postgres, Caddy data, `.env`, CA và recording; kiểm thử restore định kỳ.
- Gửi audit ra SIEM append-only. Hash chain giúp phát hiện can thiệp nhưng không thay thế WORM storage/chữ ký ngoài hệ thống.
- Triển khai staging, canary và maintenance window trước patch/reboot hàng loạt.
- Oracle Linux 7 là nền tảng legacy: khóa phiên bản dependency agent, kiểm thử riêng và lập kế hoạch nâng cấp hệ điều hành.
- Agent chạy root/SYSTEM để thực thi vận hành. Chỉ cài từ release đã ký, giới hạn quyền sửa thư mục cài đặt và theo dõi integrity.

## Kiểm thử phát triển

```bash
pnpm install
pnpm run build
node --test tests/rendered-html.test.mjs

python3 -m venv .venv
. .venv/bin/activate
pip install -r control-plane/requirements.txt -r agent/requirements.txt
PYTHONPATH=control-plane python -m unittest discover -s control-plane/tests
python -m py_compile control-plane/app/main.py agent/tram_agent.py
```

## Làm việc trên hai máy qua GitHub

```bash
# Máy thứ hai
git clone <REPOSITORY_URL>
cd <REPOSITORY_NAME>
git switch main
git pull --ff-only
```

Không đồng bộ `.env`, `deploy/pki`, certificate agent hoặc recording qua GitHub. Mỗi môi trường dùng secret/PKI riêng.

## Tài liệu nền tảng đã đối chiếu

- Windows Server 2025 OpenSSH: <https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse>
- Windows LocalAccounts PowerShell: <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/>
- Ubuntu user management: <https://documentation.ubuntu.com/server/how-to/security/user-management/>
- Ubuntu OpenSSH: <https://documentation.ubuntu.com/server/how-to/security/openssh-server/>
- Ubuntu package management: <https://documentation.ubuntu.com/server/how-to/software/package-management/>
- Ubuntu firewall: <https://documentation.ubuntu.com/server/how-to/security/firewalls/>
- Oracle Linux 8 authentication/authorization: <https://docs.oracle.com/en/operating-systems/oracle-linux/8/userauth/>
- Oracle Linux 7 administration/security: <https://docs.oracle.com/en/operating-systems/oracle-linux/7/>
- Apache Guacamole 1.6 Docker: <https://guacamole.apache.org/doc/gug/guacamole-docker.html>
- Guacamole recording: <https://guacamole.apache.org/doc/gug/recording-playback.html>
- Guacamole JSON authentication: <https://guacamole.apache.org/doc/gug/json-auth.html>
- Caddy mTLS: <https://caddyserver.com/docs/caddyfile/directives/tls>
