# Trạm Vận Hành

Control plane tự host để giám sát và vận hành tập trung Windows Server và Linux. Bản hiện tại là MVP có kiến trúc triển khai thực tế, API/agent chạy được và giao diện quản trị responsive. Trước khi dùng cho production quy mô lớn, cần kiểm thử trong môi trường staging, tích hợp IdP/vault của tổ chức và thực hiện pentest.

## Những gì đã có

- Dashboard tách tự động **Windows** và **Linux**, không yêu cầu chọn thủ công khi cài agent.
- Mỗi máy chủ có URL riêng dạng `#/linux/<hostname>` hoặc `#/windows/<hostname>`, breadcrumb quay lại danh sách và workspace toàn màn hình với các tab Tổng quan, Disk, Dịch vụ, Tài khoản, Firewall, Tiến trình, Cập nhật, Truyền file và Nhật ký.
- Inventory: hostname, OS/version, kiến trúc, IP, kernel, CPU, RAM, disk, uptime, số dịch vụ và bản vá chờ.
- Agent outbound cho Windows Server 2025, Ubuntu 24.04 và Oracle Linux 7/8.
- Enrollment một lần bằng token; agent tự tạo private key/CSR trên máy đích.
- Giao diện **Bộ cài Agent** tự sinh Linux `.run` hoặc Windows `.msi` theo đúng domain HTTPS/CA của control plane; không sửa domain bằng tay trên máy đích.
- Agent API riêng ở TCP `9443`, bắt buộc **mTLS** và xác minh certificate bằng CA nội bộ.
- Nginx trên host giữ public TCP `80/443`; Caddy chỉ xuất HTTPS web trên `127.0.0.1:3000`. Port `80` của Nginx chỉ chuyển hướng sang HTTPS.
- RBAC (`admin`, `operator`, `viewer`, `auditor`), đăng nhập Local/LDAP Domain, MFA TOTP bắt buộc, JWT ngắn hạn và Argon2 password hashing.
- Công việc có cấu trúc và allowlist; không có endpoint chạy shell tùy ý.
- Tác vụ được xếp hàng trực tiếp sau khi kiểm tra MFA/RBAC, allowlist tham số và ghi audit.
- Quản lý local user/group theo máy đang chọn: tạo/khóa/mở khóa/xóa/reset mật khẩu, tạo/xóa group và thêm/xóa thành viên.
- Scan/cài security updates, start/stop/restart service, xem process, firewall, journal/Event Log và reboot.
- SSH/RDP trong trình duyệt qua Apache Guacamole 1.6 và reverse tunnel của agent; không cần mở `22/3389` từ control plane tới máy đích.
- Truyền file một chiều qua mTLS `9443`: ClamAV trung tâm, mã hóa AES-GCM trong PostgreSQL, xếp hàng trực tiếp, kiểm tra SHA-256 và quét lại bằng Defender/ClamAV tại endpoint trước khi đưa vào inbox.
- Audit log liên kết hash để phát hiện chỉnh sửa/xóa/chèn sự kiện ngoài luồng.
- Docker Compose cho Ubuntu 24.04 với Postgres, API, dashboard, Caddy, Guacamole và guacd.

## Tự động phân loại Windows/Linux

Agent thu thập dấu vân tay hệ điều hành trước khi enroll:

- Windows: `platform.system()` kết hợp `Win32_OperatingSystem` qua CIM.
- Linux: `platform.system()` kết hợp `/etc/os-release`; Ubuntu có `ID=ubuntu`, Oracle Linux có `ID=ol`.

Control plane tự gán `os_family=windows|linux`; API và giao diện lọc theo giá trị đã xác minh. Nếu một agent đã enroll bỗng báo đổi family, máy bị chuyển sang `quarantined`, ghi audit `agent.os_family.changed` và không tự chuyển mục.

## Kiến trúc

```text
Trình duyệt ── TLS/443 ── Nginx ── HTTPS/127.0.0.1:3000 ── Caddy ─┬─ Dashboard
                                 ├─ Control Plane API ── PostgreSQL
                                 └─ Guacamole ── guacd ── relay TCP dùng một lần
                                                               │
Windows/Linux Agent ── WebSocket mTLS/9443 ── Caddy/API ───────┘
        │
        ├─ chỉ relay tới localhost:22 (Linux) hoặc localhost:3389 (Windows)
        └─ private key không rời máy; không có listener inbound của agent

Upload ── TLS/443 ── ClamAV cách ly ── AES-GCM/PostgreSQL ── job trực tiếp
        ── mTLS/9443 ── SHA-256 ── Defender/ClamAV endpoint ── inbox 0600/ACL
```

Agent chỉ cần kết nối outbound tới control plane. Không cần mở cổng inbound cho agent. `guacd`, relay TCP, ClamAV `3310` và PostgreSQL không được publish ra host. Mạng Docker `session` là internal nên `guacd` không thể đi thẳng tới subnet máy chủ. Nếu tunnel lỗi, API fail-closed và không fallback về IP quản trị.

`TunnelHub` hiện giữ trạng thái WebSocket trong bộ nhớ của tiến trình API. Vì vậy bản này phải chạy **một replica API và một Uvicorn worker**; không tăng replica/worker trước khi thay bằng tunnel broker có điều phối phân tán và session affinity.

Compose liên tục đồng bộ public root CA của HTTPS nội bộ và mTLS `9443` từ volume Caddy sang hai đích: named volume `agent_server_ca` chỉ-đọc trong API và `deploy/pki/public/server-ca.crt` trên host cho Nginx. API không mount `caddy_data`; sidecar chỉ mount thư mục public output, vì vậy không bên nào đọc được private key CA nội bộ hoặc `agent-ca.key`. Trang **Bộ cài Agent** hiển thị trạng thái CA và fail-closed cho tới khi bản public hợp lệ đã sẵn sàng.

## Cài control plane trên Ubuntu 24.04

### 1. Chuẩn bị

- Ubuntu Server 24.04 LTS x86_64/arm64.
- Tối thiểu 4 vCPU, 8 GB RAM, 80 GB disk cho lab; production cần tính riêng dung lượng recording.
- DNS `ops.example.com` trỏ tới máy control plane.
- Nginx giữ inbound TCP `80` (redirect) và `443` (operator/enrollment); Caddy giữ `9443` (agent mTLS). `3000` chỉ bind `127.0.0.1`, không mở firewall. Giới hạn `443/9443` theo VPN/subnet quản trị nếu có thể.
- Trên máy được quản lý chỉ cho outbound TCP `9443` tới control plane. Có thể cho outbound `443` trong lúc enroll.
- Chặn inbound `22/3389` từ mạng thông thường. Nếu cần đường cứu hộ, chỉ cho phép từ một bastion riêng có MFA; không cho máy được quản lý truy cập ngang sang `22/3389/445` của máy khác.
- Docker Engine và Docker Compose plugin theo tài liệu chính thức: <https://docs.docker.com/engine/install/ubuntu/>.

Docker có thể tạo rule iptables vượt qua một số rule UFW. Compose chỉ publish `127.0.0.1:3000` và `9443`; kiểm soát `9443` thêm bằng firewall upstream và `DOCKER-USER` chain.

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

Giữ `WEB_BIND_PORT=3000` và `WEB_TLS_TRUST=system` khi Nginx dùng certificate công khai (ví dụ Let's Encrypt). Certificate public phải được Windows/Linux tin cậy mặc định để bộ cài zero-touch bootstrap qua `443`; agent sau đó nhận CA riêng và vận hành bằng mTLS trực tiếp trên `9443`. File `.env` chứa secret nên không được commit; `deploy/configure-nginx.sh` backup rồi cập nhật các biến runtime không bí mật trong `.env` hiện hữu.

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

Chạy `sudo sh deploy/configure-nginx.sh DOMAIN PUBLIC_CERT PUBLIC_KEY [NGINX_OUTPUT]` để đồng bộ `.env` và render virtual host từ `deploy/nginx-dashboard.conf.example`; sau đó rebuild Compose, kiểm tra `nginx -t` rồi reload. Nginx phải xác minh upstream Caddy bằng `deploy/pki/public/server-ca.crt`; không dùng `proxy_ssl_verify off`.

Mở `https://ops.example.com` qua Nginx. Khi database chưa được cấu hình, chưa kết nối được, chưa có admin hoặc chưa có URL chuẩn, dashboard tự mở màn hình **Thiết lập lần đầu**:

1. Nhập máy chủ PostgreSQL, port, database, tài khoản, mật khẩu và chế độ SSL. Với PostgreSQL trong Compose dùng host `postgres`, port `5432` và các giá trị `POSTGRES_USER` / `POSTGRES_DB` / `POSTGRES_PASSWORD` trong `.env`.
2. Tạo tài khoản admin local đầu tiên với mật khẩu tối thiểu 14 ký tự.
3. Nhập URL chính thức của dashboard và `SETUP_TOKEN` nếu đã cấu hình.

API kiểm tra kết nối, tạo schema, admin, cấu hình hệ thống và audit event trong một luồng. Sau khi hoàn tất, wizard bị khóa và dashboard chuyển sang màn hình đăng nhập. Toàn bộ dữ liệu nghiệp vụ được lưu trong PostgreSQL; volume `api_config` chỉ giữ thông tin bootstrap và khóa mã hóa không nên lưu chung với dữ liệu đã mã hóa.

## Cài agent

### 1. Tạo bộ cài zero-touch trên dashboard

Đăng nhập bằng `admin`, mở **Bộ cài Agent** và kiểm tra URL control plane. URL phải là origin HTTPS thật đang mở trong trình duyệt, ví dụ `https://ops.company.com`; DNS, `OPS_DOMAIN`, TLS/Nginx và Caddy phải hoạt động trước khi lưu.

Nhập tên máy/ticket, chọn thời hạn 15–60 phút rồi tải đúng định dạng:

- Linux: `TramAgent-Linux-<label>.run`. Chép qua kênh quản trị tin cậy và chạy:

  ```bash
  chmod +x TramAgent-Linux-*.run
  sudo ./TramAgent-Linux-*.run
  ```

- Windows: một file `TramAgent--...msi`. **Không đổi tên file**; chạy bằng Administrator. MSI chứa executable độc lập, cài service `TramVanHanhAgent` dưới `LocalSystem`, đặt `StartType=Automatic`, khởi động ngay và tự restart khi lỗi. Windows Server không cần cài Python.

Bộ cài không chứa private key/certificate agent dài hạn. Nó chỉ mang locator, chế độ xác minh TLS và claim ngẫu nhiên dùng một lần; private key P-256 được sinh trên máy đích. Với `WEB_TLS_TRUST=system`, bootstrap `443` dùng chuỗi tin cậy công khai của Nginx; sau khi claim, mọi kết nối Agent dùng CA riêng và mTLS `9443`. Claim sai hệ điều hành, hết hạn, đã dùng hoặc replay đều bị từ chối và ghi audit. Windows/Linux tự vào đúng mục dựa trên inventory thực tế.

Nếu thay domain sau khi đã có agent, bộ cài mới dùng domain mới nhưng agent cũ vẫn giữ endpoint/CA cũ. Phải lập kế hoạch migrate agent cũ; không xóa domain cũ trước khi chúng đã kết nối qua domain mới.

MSI trong repository là artifact generic, không chứa domain/token. Trước production cần cấu hình GitHub secrets `WINDOWS_SIGNING_PFX_BASE64` và `WINDOWS_SIGNING_PASSWORD`, chạy workflow **Build Windows agent MSI**, thay artifact trong `agent/windows/TramVanHanhAgent.msi`, rồi rebuild API. Không lưu PFX/code-signing password trên control plane.

### 2. Enrollment token thủ công (đường nâng cao/break-glass)

Đăng nhập lấy access token:

```bash
ACCESS_TOKEN=$(curl -fsS https://ops.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASSWORD"}' | jq -r .access_token)
```

Token dùng một lần, hết hạn sau 24 giờ:

```bash
curl -fsS https://ops.example.com/api/v1/enrollment-tokens \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"server-batch-01","expires_hours":24,"max_uses":1}'
```

Có thể thêm `"expected_os_family":"windows"` hoặc `"linux"` để token chỉ dùng được đúng loại máy.

### 3. Ubuntu 24.04 / Oracle Linux 7, 8 — cài thủ công

Trên Ubuntu, bộ cài tự cài Python 3, `venv`, OpenSSH Server và ClamAV. Trên Oracle Linux 8, chỉ bật repository EPEL đã được tổ chức phê duyệt rồi cài ClamAV/cập nhật signature. Oracle Linux 7 có ClamAV cũ trong developer EPEL; không dùng bản EOL cho production — cần endpoint scanner còn được nhà cung cấp hỗ trợ, nếu không truyền file sẽ fail-closed.

```bash
sudo sh agent/install-linux.sh
sudo /opt/tram-agent/venv/bin/python /opt/tram-agent/tram_agent.py \
  enroll --server https://ops.example.com \
  --server-ca /path/server-ca.crt --token 'tvo_ONE_TIME_TOKEN'
sudo systemctl enable --now tram-agent
sudo systemctl status tram-agent
```

Máy sẽ tự xuất hiện trong **Máy chủ Linux**. Ubuntu được nhận diện từ `ID=ubuntu`; Oracle Linux từ `ID=ol`.

### 4. Windows Server 2025 — cài thủ công

Chạy PowerShell 64-bit bằng quyền Administrator. Đường thủ công cần Python 3.11+; script đăng ký Windows Service `TramVanHanhAgent` chạy dưới `LocalSystem`, `Automatic` và tự restart khi lỗi. Không còn dùng Scheduled Task.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\agent\install-windows.ps1 `
  -Server "https://ops.example.com" `
  -ServerCA "C:\SecureBootstrap\server-ca.crt" `
  -EnrollmentToken "tvo_ONE_TIME_TOKEN"
```

Máy sẽ tự xuất hiện trong **Máy chủ Windows**. RDP phải được bật và gắn certificate; firewall không cần cho phép `3389` từ control plane vì agent chỉ nối tới listener cục bộ. Microsoft Defender phải hoạt động để nhận file.

## SSH/RDP và recording

1. Chọn server trong dashboard.
2. Linux hiển thị **Mở SSH**; Windows hiển thị **Remote Desktop**.
3. Nhập credential dùng cho đúng phiên. Password được đưa vào JSON Guacamole có chữ ký HMAC-SHA256, mã hóa AES-CBC và hết hạn sau 2 phút; API không lưu password và không ghi password vào audit.
4. API tạo listener TCP dùng một lần trên mạng Docker internal, yêu cầu agent mở stream mTLS tới đúng dịch vụ local và chỉ trả địa chỉ relay cho Guacamole sau khi stream đã sẵn sàng. Nhờ vậy lỗi `sshd`/RDP local hoặc Agent không mở được stream sẽ được báo ngay trên dashboard thay vì chỉ hiện lỗi nội bộ của Guacamole. Agent từ chối mọi host/port tùy ý.
5. `guacd` ghi native graphical recording vào `RECORDING_DIR`; SSH ghi thêm typescript.
6. Vào **Nhật ký kiểm toán → Video ghi session → Xem lại** để phát trực tiếp recording gốc trong trình duyệt.

Admin có thể chọn một hoặc nhiều recording và tạo yêu cầu xóa. Yêu cầu được lưu trong PostgreSQL; chính admin tạo yêu cầu không được tự duyệt. Chỉ sau khi một admin thứ hai duyệt thì API mới xóa graphical recording và typescript khỏi `RECORDING_DIR`, đồng thời ghi request/approval/kết quả vào audit. Đây là thao tác duy nhất trên dashboard dùng phê duyệt hai quản trị viên; các resource job khác vẫn chạy trực tiếp theo RBAC/MFA/allowlist.

Recording gốc của Guacamole không cần re-encode, giữ nguyên dữ liệu hiển thị ở độ phân giải trình duyệt yêu cầu và thường nhỏ hơn video truyền thống. Object storage retention và legal hold vẫn là hạng mục production tiếp theo. Không bật `ignore-cert` cho RDP; fingerprint certificate RDP do agent thu thập được pin trong Guacamole. SSH host key cũng được pin. Clipboard hai chiều, SFTP và RDP drive/printing đều bị tắt; file chỉ đi qua pipeline đã quét.

Nếu SSH không mở được, không mở inbound `22`. Trên máy Linux đích kiểm tra `systemctl status ssh` (Ubuntu) hoặc `systemctl status sshd` (Oracle Linux), listener `127.0.0.1:22` và log `journalctl -u tram-agent`. Trên control plane kiểm tra `docker compose ... logs api guacamole guacd`; API sẽ phân biệt lỗi Agent/sshd trước khi chuyển trình duyệt sang Guacamole.

## Truyền file an toàn

1. Chọn máy chủ, tải file tối đa 50 MiB và nhập ticket/lý do.
2. API giữ upload trong `/tmp` container gắn `noexec,nosuid,nodev`, gửi bytes qua `INSTREAM` tới ClamAV trên mạng Docker riêng. Socket `3310` không được public.
3. File sạch được mã hóa AES-GCM có AAD gắn với transfer/server/SHA-256 rồi lưu trong PostgreSQL. File nhiễm hoặc scanner lỗi không được lưu nội dung.
4. API tạo ngay job `file.deliver` ở trạng thái `queued`; Agent nhận ở lần check-in kế tiếp.
5. Đúng agent tải file qua API mTLS `9443`, kiểm tra kích thước/SHA-256, quét lại bằng Microsoft Defender hoặc ClamAV endpoint, sau đó publish không ghi đè vào `%ProgramData%\TramVanHanh\Inbox` hoặc `/var/lib/tram-agent/inbox`.
6. Sau khi agent báo thành công/thất bại, ciphertext bị xóa khỏi PostgreSQL; metadata, hash và audit được giữ lại. Không có luồng tải file từ server về dashboard hoặc server-sang-server.

Không hệ thống antivirus nào đảm bảo chặn tuyệt đối zero-day. Các lớp trên giảm mạnh khả năng lây nhiễm chéo; production vẫn cần EDR, application allowlisting (WDAC/AppLocker/SELinux), phân đoạn mạng và kiểm thử pentest.

## LDAP Domain Login và MFA

1. Đăng nhập bằng admin Local và mở **Truy cập & Vai trò**.
2. Nhập LDAP/Active Directory host, Base DN, Bind DN, service-account password, chọn LDAPS và dán CA certificate nếu dùng enterprise/private CA.
3. Bật **Domain Login**, lưu cấu hình, sau đó dùng tab **Domain Login** ở màn hình đăng nhập.
4. Lần đầu mỗi tài khoản Local hoặc Domain đăng nhập thành công, hệ thống bắt buộc quét QR TOTP và xác minh mã 6 số trước khi cấp JWT.

Mật khẩu Bind DN và TOTP secret được mã hóa bằng `JOB_SECRET_KEY` trước khi lưu PostgreSQL. Bắt buộc dùng LDAPS có certificate được API container tin cậy ở production.

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

Tác vụ đặc quyền được tạo ở trạng thái `queued` và Agent nhận ở lần check-in kế tiếp. API không còn endpoint approve; RBAC, MFA, validation tham số và audit vẫn bắt buộc.

Nút **Extend** luôn hiển thị trên partition/LV. Nút chỉ bật khi Agent xác nhận có ít nhất 1 MiB dung lượng mở rộng an toàn: Windows cần vùng unallocated liền kề partition, còn Linux LVM cần dung lượng trống trong Volume Group. Root LV được phép extend nhưng vẫn bị khóa xóa; partition boot/root trực tiếp không được tự động extend. Ứng dụng không tự di chuyển partition Recovery của Windows.

Mọi thao tác nghiệp vụ của người dùng (đăng nhập/MFA, cấu hình, agent, job vận hành, file, phiên SSH/RDP và recording) được ghi vào `audit_events` trong PostgreSQL với actor, IP nguồn, kết quả, tham số an toàn và chuỗi hash. Giao diện audit phân trang 500 bản ghi mỗi lần. Bản ghi quá 30 ngày được dọn lúc API khởi động và mỗi giờ; hash cuối của phần đã xóa được giữ trong `system_settings.audit_retention_anchor` để duy trì dấu vết liên kết.

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
python -m unittest discover -s agent/tests
python -m py_compile control-plane/app/main.py control-plane/app/tunnel.py control-plane/app/file_security.py agent/tram_agent.py
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
- Caddy WebSocket reverse proxy: <https://caddyserver.com/docs/caddyfile/directives/reverse_proxy>
- ClamAV `INSTREAM`: <https://docs.clamav.net/manual/Usage/ClamdProtocol.html>
- Microsoft Defender `MpCmdRun`: <https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus>
- OWASP File Upload Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
