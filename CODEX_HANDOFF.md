# Bàn giao Codex — 14/08/2026

## Repository và trạng thái

- Repository: `https://github.com/anhnn1639/dashboard-mgmt.git`
- Nhánh triển khai: `main`; người dùng cho phép commit/push trực tiếp thay đổi hoàn chỉnh.
- Thay đổi Nginx/port 3000 và Agent 0.4.1: `73bbc4b Run dashboard behind Nginx on port 3000`; MSI đã bundle vào main tại `3df6d06`.
- Agent mới nhất: `0.4.1`.
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
- SHA-256: `AF75F260FB3CB714193D2D8E7F3AC286F525893E4F0584520FF6BED3BFF1DC20`.
- Build PyInstaller + WiX và upload artifact thành công trên GitHub Actions run `31772798824`.
- Workflow: `.github/workflows/build-agent-msi.yml`.
- Workflow hỗ trợ ký EXE và MSI nếu repository có secrets:
  - `WINDOWS_SIGNING_PFX_BASE64`
  - `WINDOWS_SIGNING_PASSWORD`
- Artifact hiện tại **chưa ký Authenticode** vì chưa có code-signing certificate. Trước production phải ký lại, thay MSI trong repo, kiểm tra `Get-AuthenticodeSignature`, rồi rebuild API. Không đặt PFX/private signing key trên dashboard.
- Administrative extraction `msiexec /a` trên laptop phát triển bị Windows Installer/sandbox treo; đúng process thử nghiệm đã được dừng và không cài service lên laptop. Phải cài/reboot/uninstall MSI trên Windows Server staging.

## Reverse tunnel và truyền file vẫn giữ nguyên

- Agent outbound WebSocket mTLS `9443`; API/Guacamole không kết nối trực tiếp IP máy đích.
- Agent chỉ relay `127.0.0.1:22` cho SSH hoặc `127.0.0.1:3389` cho RDP, tối đa 4 tunnel; không fallback trực tiếp.
- Pin SSH host key/RDP certificate, tắt clipboard/SFTP/RDP drive/printing, giữ recording.
- File một chiều: giới hạn 50 MiB, ClamAV trung tâm, AES-GCM PostgreSQL, duyệt bốn mắt, SHA-256 và Defender/ClamAV endpoint; không auto-run/overwrite/server-to-server.
- Payload file xóa sau kết quả hoặc hết hạn 24 giờ; scanner lỗi thì fail-closed.

## Nginx, TLS và firewall

- Nginx host giữ public `80/tcp` (redirect) và `443/tcp` (dashboard/API/Guacamole/enrollment/bootstrap claim).
- Compose map Caddy HTTPS `443` thành `127.0.0.1:${WEB_BIND_PORT:-3000}`; không publish port Caddy `80/443` trực tiếp.
- `9443/tcp`: agent mTLS check-in/job/tunnel/file.
- Nginx reverse proxy tới `https://127.0.0.1:3000`, bật SNI và xác minh bằng `deploy/pki/server-ca.crt`; không dùng `proxy_ssl_verify off`.
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

`compose.yaml` đã đổi API build context sang repository root để copy agent source và MSI vào `/opt/tram-agent-assets`; bắt buộc rebuild container `api`, không chỉ restart.

`compose.yaml` cũng không còn tranh host port `80/443` với Nginx: web Caddy bind loopback `3000`, còn `9443` vẫn public cho agent mTLS. Mẫu virtual host nằm ở `deploy/nginx-dashboard.conf.example`; certificate public của Nginx phải được endpoint tin cậy mặc định.

Kết quả mong đợi:

- Trang **Bộ cài Agent** hiển thị đúng URL production, Agent `0.4.1`, Linux available và Windows MSI available.
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
9. Retest SSH/RDP recording và file sạch/EICAR/scanner offline.
10. Test uninstall/upgrade MSI và xác nhận không để lộ claim/private key trong log.

## Kiểm thử local đã đạt

- Control plane `14/14`, gồm configured domain, bundle generation, CA pin, OS binding và replay rejection.
- Agent security `6/6`, gồm parser locator MSI và bootstrap qua TLS public của Nginx.
- ESLint pass.
- Vinext production build pass.
- Python `py_compile` pass.
- XML/YAML/PowerShell syntax pass.
- GitHub Actions run cuối trên `main` là `31772974612`, pass toàn bộ; bước ký EXE/MSI được skip đúng thiết kế vì repository chưa cấu hình code-signing secrets.

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
