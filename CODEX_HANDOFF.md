# Bàn giao Codex — 14/08/2026

## Repository và trạng thái

- Repository: `https://github.com/anhnn1639/dashboard-mgmt.git`
- Nhánh triển khai: `main`; người dùng cho phép commit/push trực tiếp thay đổi hoàn chỉnh.
- Thay đổi Nginx/port 3000 và Agent 0.4.1: `73bbc4b Run dashboard behind Nginx on port 3000`; MSI đã bundle vào main tại `3df6d06`.
- Đồng bộ `.env`/Nginx và version contract: `a38d722 Synchronize runtime config and release version`; MSI đồng bộ đã bundle tại `b7fada2`.
- Agent mới nhất: `0.4.1`.
- Bản sửa mới nhất tách đúng label/input của form **Bộ cài Agent**, hiển thị lỗi màu đỏ, công khai trạng thái `agentTlsCaAvailable` và thay luồng export CA một lần bằng sidecar đồng bộ liên tục.
- Dashboard mới mở máy chủ bằng URL hash riêng và workspace toàn màn hình; breadcrumb quay lại đúng danh sách Linux/Windows. Các tab Tổng quan, Disk, Dịch vụ, Tài khoản, Firewall, Tiến trình, Cập nhật, Truyền file và Nhật ký dùng trực tiếp các action allowlist hiện có.
- Lỗi SSH Guacamole ngày 16/08 đã xác định ở lớp Docker DNS, trước tunnel/sshd: container `guacamole` và `guacd` cùng network `tram-van-hanh_session` nhưng endpoint cũ có `Aliases=null`, nên `getent hosts guacd` rỗng và Tomcat báo `UnknownHostException: guacd`. Compose hiện khai báo alias `guacd`/`guacamole` tường minh và chỉ khởi động Guacamole sau khi `guacd` healthy.
- API có lịch sử job theo từng máy chủ và chỉ trả output cho role được phép xem action đó; kết quả `inventory.collect` hợp lệ cập nhật inventory bền vững trong PostgreSQL.
- `agent/VERSION` là nguồn version chung cho runtime Agent, Linux bundle, API status và WiX MSI; workflow truyền giá trị này vào PyInstaller/WiX và test chống lệch version.
- Luôn đọc `AGENTS.md`, xem status/diff trước khi sửa; không reset/xóa local change chưa xác định.

## Zero-touch Agent đã triển khai

- Admin có trang **Bộ cài Agent** để xem/sửa origin HTTPS của control plane và tải Linux `.run` hoặc Windows `.msi`.
- API lấy URL từ PostgreSQL `system_settings.dashboard_url`; không hard-code `ops.example.com`. URL chỉ nhận origin HTTPS, admin phải mở dashboard qua chính hostname muốn lưu.
- Khi đổi domain mà đã có agent, UI/API bắt buộc xác nhận vì agent cũ vẫn giữ endpoint và CA cũ.
- Mỗi bộ cài có claim ngẫu nhiên 256-bit, hết hạn 5–60 phút, dùng một lần và khóa theo `windows|linux`. Replay, claim hết hạn hoặc nhầm OS đều fail-closed/audit.
- Private key P-256 và CSR được sinh tại endpoint. Bộ cài chỉ mang locator, SHA-256 pin của CA và claim ngắn hạn; không chứa client private key/certificate dài hạn.
- Linux `.run` tự giải nén, cài dependency/ClamAV/systemd, enroll, xóa bootstrap secret và start service.
- Windows dùng MSI generic; API không sửa bytes MSI mà chỉ phát nó dưới tên chứa locator/claim/CA pin, nên có thể giữ chữ ký Authenticode. Không được đổi tên file trước khi cài.
- MSI cài executable PyInstaller độc lập; Windows Server không cần Python. Service `TramVanHanhAgent` chạy `LocalSystem`, `Automatic`, phụ thuộc TCP/IP, start lúc cài và restart sau 30 giây nếu lỗi.
- `agent/install-windows.ps1` thủ công cũng đã chuyển từ Scheduled Task sang Windows Service.
- Windows/Linux vẫn tự vào đúng mục dựa trên inventory thực tế; server từ MSI Linux không thể dùng claim Windows và ngược lại.
- Khi đặt `WEB_TLS_TRUST=system`, bộ cài bootstrap qua certificate public của Nginx trên `443`; response enrollment vẫn cấp CA riêng để mọi lưu lượng Agent sau đó dùng mTLS trực tiếp trên `9443`.

## MSI artifact

- File: `agent/windows/TramVanHanhAgent.msi`
- Kích thước: `13,582,336` bytes.
- SHA-256: `080BF23ADEA876F1801916350D50E8A001097BDC8C1D6895301EABDB7F6B40DC`.
- Build PyInstaller + WiX và upload artifact thành công trên GitHub Actions run `31779167705`.
- Workflow: `.github/workflows/build-agent-msi.yml`.
- Workflow hỗ trợ ký EXE và MSI nếu repository có secrets:
  - `WINDOWS_SIGNING_PFX_BASE64`
  - `WINDOWS_SIGNING_PASSWORD`
- Artifact hiện tại **chưa ký Authenticode** vì chưa có code-signing certificate. Trước production phải ký lại, thay MSI trong repo, kiểm tra `Get-AuthenticodeSignature`, rồi rebuild API. Không đặt PFX/private signing key trên dashboard.
- Administrative extraction `msiexec /a` trên laptop phát triển bị Windows Installer/sandbox treo; đúng process thử nghiệm đã được dừng và không cài service lên laptop. Phải cài/reboot/uninstall MSI trên Windows Server staging.

## Reverse tunnel và truyền file vẫn giữ nguyên

- Agent outbound WebSocket mTLS `9443`; API/Guacamole không kết nối trực tiếp IP máy đích.
- Agent chỉ relay `127.0.0.1:22` cho SSH hoặc `127.0.0.1:3389` cho RDP, tối đa 4 tunnel; không fallback trực tiếp.
- API gửi lệnh mở tunnel và chờ Agent gắn stream mTLS thành công trước khi trả relay port cho Guacamole. Điều này loại bỏ race khiến `guacd` kết nối trước Agent và biến lỗi sshd/RDP local thành HTTP 409 có hướng dẫn; Agent 0.4.1 hiện tại tương thích, không cần cài lại.
- Pin SSH host key/RDP certificate, tắt clipboard/SFTP/RDP drive/printing, giữ recording.
- File một chiều: giới hạn 50 MiB, ClamAV trung tâm, AES-GCM PostgreSQL, duyệt bốn mắt, SHA-256 và Defender/ClamAV endpoint; không auto-run/overwrite/server-to-server.
- Payload file xóa sau kết quả hoặc hết hạn 24 giờ; scanner lỗi thì fail-closed.

## Nginx, TLS và firewall

- Nginx host giữ public `80/tcp` (redirect) và `443/tcp` (dashboard/API/Guacamole/enrollment/bootstrap claim).
- Compose map Caddy HTTPS `443` thành `127.0.0.1:${WEB_BIND_PORT:-3000}`; không publish port Caddy `80/443` trực tiếp.
- `9443/tcp`: agent mTLS check-in/job/tunnel/file.
- Nginx reverse proxy tới `https://127.0.0.1:3000`, bật SNI và xác minh bằng `deploy/pki/public/server-ca.crt`; không dùng `proxy_ssl_verify off`.
- `caddy-ca-export` không có network, liên tục chép public root Caddy sang named volume `agent_server_ca` cho API và `deploy/pki/public/server-ca.crt` cho Nginx. API chỉ mount named volume read-only; exporter chỉ mount thư mục public output nên cả hai đều không thấy `caddy_data` private key hoặc `deploy/pki/agent-ca.key`.
- `.env` luôn bị Git ignore vì chứa secret. `deploy/configure-nginx.sh` backup và upsert ba biến không bí mật `OPS_DOMAIN`, `WEB_BIND_PORT=3000`, `WEB_TLS_TRUST=system`, đồng thời render Nginx từ template được track; không push/ghi đè secret.
- Không public `3310`, `4822`, `5432` hoặc relay tạm.
- Agent chỉ cần outbound `443` khi bootstrap và `9443` khi vận hành; không cần inbound agent.
- Chỉ đóng `22/3389` thông thường sau khi tunnel staging đã chạy; break-glass chỉ từ bastion MFA.
- API hiện giữ TunnelHub in-memory: chỉ chạy một API replica/Uvicorn worker.

## Xử lý lỗi `git pull` trong ảnh người dùng

Máy `/home/system/dashboard-mgmt` có local change ở `agent/install-linux.sh`, nên pull bị chặn. Không reset cả repository. Kiểm tra và backup đúng file:

```bash
cd /home/system/dashboard-mgmt
git diff -- agent/install-linux.sh
cp -a agent/install-linux.sh /root/install-linux.sh.before-zero-touch
git restore -- agent/install-linux.sh
git pull --ff-only origin main
```

Nếu diff có nội dung cần giữ, trước khi restore lưu patch:

```bash
git diff -- agent/install-linux.sh > /root/install-linux.local.patch
```

Sau pull, không áp patch cũ nguyên xi vì installer Linux mới có bootstrap zero-touch; chỉ đối chiếu phần local thực sự cần giữ.

## Triển khai control plane tiếp theo

Bản test PostgreSQL trong Docker:

```bash
cd /home/system/dashboard-mgmt
git pull --ff-only origin main
git log -3 --oneline

docker compose -f compose.yaml -f compose.test.yaml pull
docker compose -f compose.yaml -f compose.test.yaml up -d --build
docker compose -f compose.yaml -f compose.test.yaml ps
docker compose -f compose.yaml -f compose.test.yaml logs --tail=150 caddy api dashboard clamav guacamole guacd
```

Riêng bản workspace/tunnel hiện tại chỉ cần recreate `api` và `dashboard`:

```bash
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api guacamole guacd
```

Máy đã tạo `guacd`/`guacamole` trước bản sửa Docker DNS phải recreate đúng hai container để endpoint nhận alias mới:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --force-recreate guacd guacamole
docker compose -f compose.yaml -f compose.test.yaml exec guacamole getent hosts guacd
```

Lệnh cuối phải trả về IP nội bộ và tên `guacd`. Nếu rỗng, kiểm tra `docker inspect` của hai container; cả hai phải cùng network `*_session`, trong đó `guacd` có alias/DNS name `guacd`.

Máy nâng cấp từ bản cũ bị lỗi `The agent TLS CA is not available for package generation` phải recreate API và CA exporter để tạo named volume/mount mới:

```bash
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api caddy-ca-export
docker compose -f compose.yaml -f compose.test.yaml ps caddy-ca-export api
docker compose -f compose.yaml -f compose.test.yaml logs --tail=50 caddy-ca-export
docker compose -f compose.yaml -f compose.test.yaml exec api \
  python -c "from pathlib import Path; assert Path('/run/server-ca/server-ca.crt').stat().st_size > 0"
sudo sh deploy/configure-nginx.sh DOMAIN PUBLIC_CERT PUBLIC_KEY /etc/nginx/sites-available/tram-ops
sudo nginx -t && sudo systemctl reload nginx
```

`compose.yaml` đã đổi API build context sang repository root để copy agent source và MSI vào `/opt/tram-agent-assets`; bắt buộc rebuild container `api`, không chỉ restart.

`compose.yaml` cũng không còn tranh host port `80/443` với Nginx: web Caddy bind loopback `3000`, còn `9443` vẫn public cho agent mTLS. Dùng `deploy/configure-nginx.sh` thay vì sửa tay nhiều file; certificate public của Nginx phải được endpoint tin cậy mặc định.

Kết quả mong đợi:

- Trang **Bộ cài Agent** hiển thị đúng URL production, Agent `0.4.1`, Linux available và Windows MSI available.
- `agentTlsCaAvailable=true`; không còn cảnh báo CA và label/ô nhập không dính nhau.
- Tải Linux trả `.run`; tải Windows trả MSI có tên dài bắt đầu `TramAgent--`.
- Không có domain `example` trong config sinh ra nếu `dashboard_url` đã đặt đúng.
- Không public port nội bộ.

Production PostgreSQL bên ngoài dùng `compose.external.yaml` thay `compose.test.yaml`.

## Smoke test bắt buộc

1. Mở dashboard bằng domain thật, vào **Bộ cài Agent**, lưu đúng URL HTTPS.
2. Tải Linux `.run`, cài Ubuntu staging; xác nhận service running, agent `0.4.1`, tự vào Linux và `tunnelOnline=true`.
3. Dùng lại cùng `.run` trên máy khác: claim phải bị `401`.
4. Tải MSI, giữ nguyên tên, cài bằng Administrator trên Windows Server 2025 staging.
5. Kiểm tra:

   ```powershell
   Get-Service TramVanHanhAgent
   Get-CimInstance Win32_Service -Filter "Name='TramVanHanhAgent'" | Select Name,State,StartMode,PathName
   Get-Content "$env:ProgramData\TramVanHanh\agent.log" -Tail 100
   ```

6. Reboot Windows, xác nhận service và tunnel tự online lại.
7. Đổi tên một MSI mới trước khi cài: bootstrap phải fail, không enroll nhầm control plane.
8. Xác nhận claim Windows không dùng được trên Linux và replay bị từ chối.
9. Retest SSH/RDP recording và file sạch/EICAR/scanner offline. Khi mở SSH, xác nhận API có log `agent stream prepared`; nếu còn lỗi Guacamole, lấy đồng thời log `api guacamole guacd` để tách lỗi credential/host-key/recording.
10. Test uninstall/upgrade MSI và xác nhận không để lộ claim/private key trong log.

## Kiểm thử local đã đạt

- Control plane `16/16`, gồm configured domain, bundle generation, CA pin, trạng thái/fail-closed khi public CA bị thiếu, OS binding, replay rejection, lịch sử/output job và tunnel chuẩn bị trước Guacamole.
- Agent security `7/7`, gồm parser locator MSI, bootstrap qua TLS public của Nginx và version contract.
- `deploy/configure-nginx.sh` integration test chạy lặp hai lần: giữ nguyên secret, không nhân đôi key và tạo backup đúng.
- ESLint pass.
- Vinext production build pass.
- Render trực quan form bộ cài pass: label dùng grid, gap `7px`, input/select cao `40px`; tab kiểm thử và server tạm đã đóng/xóa.
- Render trực quan workspace máy chủ pass: bố cục toàn vùng nội dung, breadcrumb, action SSH, tab ngang lớn, bảng dịch vụ và form thao tác hiển thị đúng.
- Python `py_compile` pass.
- XML/YAML/PowerShell syntax pass.
- Máy phát triển không có Docker; `compose.yaml` đã parse/kiểm tra cấu trúc bằng PyYAML, còn `docker compose config` và recreate thực tế phải xác nhận trên Ubuntu deployment.
- GitHub Actions run cuối trên `main` là `31779341117`, pass toàn bộ; bước ký EXE/MSI được skip đúng thiết kế vì repository chưa cấu hình code-signing secrets.

## Ưu tiên sau smoke test

1. Cấu hình enterprise/EV code-signing certificate cho workflow và thay artifact unsigned.
2. Lập luồng migrate domain/CA có dual-endpoint overlap cho agent cũ; không tắt domain cũ đột ngột.
3. Tích hợp Vault/LAPS cho credential SSH/RDP.
4. Immutable/WORM storage cho recording/audit.
5. Distributed tunnel broker trước khi scale API.
6. CRL/OCSP và certificate rotation tự động.
7. EDR/WDAC/AppLocker/SELinux, micro-segmentation và pentest độc lập.

## Nguyên tắc không phá vỡ

- Không thêm shell/PowerShell tùy ý hoặc destination tunnel tùy ý.
- Không bỏ mTLS, request signature, TLS pin/hostname verification, RBAC, bốn mắt hoặc audit.
- Không log/commit `.env`, password, raw claim, token, private key, DB URL có password, PFX hoặc recording.
- Không cho file tự chạy và không bật lại clipboard/SFTP/RDP drive.
- Không public ClamAV, guacd, PostgreSQL hoặc relay.
- Không sửa bytes MSI riêng theo từng server vì sẽ phá chữ ký; locator dùng một lần phải nằm trong tên file.
