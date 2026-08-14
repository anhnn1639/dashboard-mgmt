# Bàn giao Codex — 14/08/2026

## Repository và quy ước

- Repository: `https://github.com/anhnn1639/dashboard-mgmt.git`
- Nhánh làm việc/triển khai: `main`
- Commit tính năng mới nhất: `3941392 Route remote access through secure agent tunnels`
- Agent mới nhất: `0.3.0`
- Người dùng đã cho phép commit và push trực tiếp từng thay đổi hoàn chỉnh lên `main`; không tạo PR nếu chưa được yêu cầu.
- Luôn đọc `AGENTS.md`, xem `git status` và diff trước khi sửa. Không dùng `git reset --hard` hoặc xóa thay đổi chưa xác định.

## Thay đổi bảo mật đã hoàn thành

### SSH/RDP qua reverse tunnel của agent

- Agent duy trì WebSocket outbound qua `wss://OPS_DOMAIN:9443`, được bảo vệ bằng mTLS và chữ ký ECDSA theo request/handshake.
- Khi người vận hành mở SSH/RDP, API tạo một TCP listener dùng một lần trên Docker network `session`; `guacd` không kết nối trực tiếp tới IP máy đích.
- Agent chỉ có thể relay tới `127.0.0.1:22` cho SSH hoặc `127.0.0.1:3389` cho RDP. Agent từ chối host/port tùy ý và giới hạn 4 tunnel đồng thời.
- Không có fallback trực tiếp tới `server.address:22/3389`. Nếu agent tunnel offline, giao diện khóa nút kết nối và API fail-closed.
- SSH pin host key. RDP pin certificate fingerprint do agent thu thập, dùng NLA và không bật `ignore-cert`.
- Clipboard hai chiều, Guacamole SFTP, RDP drive, upload/download và printing đều bị tắt. Recording vẫn được giữ.

### Truyền file một chiều có kiểm soát

- Dashboard cho phép operator/admin upload tối đa 50 MiB vào đúng máy đang chọn và bắt buộc nhập lý do/ticket.
- Caddy chặn request body lớn hơn 55 MB trước API; API tự kiểm tra giới hạn 50 MiB và filename an toàn.
- ClamAV trung tâm quét bằng `INSTREAM` trên Docker network riêng; TCP `3310` không được publish. Scanner lỗi thì fail-closed.
- File sạch được mã hóa AES-GCM trong PostgreSQL; AAD ràng buộc transfer ID, server ID và SHA-256.
- Job `file.deliver` là critical và bắt buộc quy tắc bốn mắt; người upload không tự duyệt.
- Chỉ đúng agent tải file qua mTLS `9443`, kiểm tra size/SHA-256 và quét lại bằng Microsoft Defender hoặc ClamAV endpoint.
- File được đưa vào inbox không ghi đè, không tự chạy:
  - Linux: `/var/lib/tram-agent/inbox`, directory `0700`, file `0600`.
  - Windows: `%ProgramData%\TramVanHanh\Inbox`, ACL chỉ SYSTEM/Administrators và gắn Mark-of-the-Web.
- Ciphertext bị xóa ngay khi agent báo thành công/thất bại; payload chưa xử lý hết hạn sau 24 giờ. Chỉ giữ metadata/hash/audit.
- Không có chiều tải từ server về dashboard và không có server-to-server transfer.

### TLS và mạng

- `80/tcp`: chỉ redirect sang HTTPS.
- `443/tcp`: dashboard, API, Guacamole và enrollment qua HTTPS.
- `9443/tcp`: agent mTLS cho check-in, job, reverse tunnel và file download.
- Không public `3310`, `4822`, `5432` hoặc port relay tạm.
- `guacd` và relay ở network `session` internal. API bind relay bằng alias `tunnel-relay`, không bind lên mọi interface container.
- Caddy dùng CA nội bộ; máy quản trị và agent phải tin cậy `deploy/pki/server-ca.crt` qua kênh bootstrap an toàn.

## Triển khai bắt buộc tiếp theo trên Ubuntu control plane

Máy test đang dùng PostgreSQL trong Docker:

```bash
cd /home/ubuntu/dashboard-mgmt
git pull --ff-only origin main
git log -3 --oneline

docker compose -f compose.yaml -f compose.test.yaml pull
docker compose -f compose.yaml -f compose.test.yaml up -d --build
docker compose -f compose.yaml -f compose.test.yaml ps
docker compose -f compose.yaml -f compose.test.yaml logs --tail=150 caddy api clamav guacamole guacd
```

Production PostgreSQL bên ngoài dùng `compose.external.yaml` thay `compose.test.yaml` và phải có `EXTERNAL_DATABASE_URL` hợp lệ.

Kết quả mong đợi:

- `caddy`, `api`, `dashboard`, `guacamole`, `guacd`, `clamav` và PostgreSQL test healthy/running.
- `https://OPS_DOMAIN` mở được sau khi import CA nội bộ vào Root CA máy quản trị.
- `https://OPS_DOMAIN:9443` không chấp nhận client không có certificate agent.
- Không có port host `3310`, `4822`, `5432` hoặc relay ngẫu nhiên.

Không chạy nhiều API replica/Uvicorn worker. `TunnelHub` hiện giữ WebSocket trong bộ nhớ; phải giữ một API process cho tới khi có distributed tunnel broker và session affinity.

## Nâng cấp agent hiện có

### Ubuntu 24.04

```bash
sudo apt-get update
sudo apt-get install -y clamav clamav-freshclam
sudo cp /home/ubuntu/dashboard-mgmt/agent/tram_agent.py /opt/tram-agent/tram_agent.py
sudo /opt/tram-agent/venv/bin/pip install --no-cache-dir -r /home/ubuntu/dashboard-mgmt/agent/requirements.txt
sudo systemctl restart tram-agent
sudo systemctl status tram-agent --no-pager
sudo journalctl -u tram-agent -n 100 --no-pager
```

Agent đã enroll trước đó không cần token mới nếu certificate/key và `server-ca.crt` còn hợp lệ. Log phải có `agent reverse tunnel is online`, agent version trên dashboard là `0.3.0`.

Oracle Linux 8 phải cài ClamAV từ repository EPEL đã được tổ chức phê duyệt và cập nhật signature. Oracle Linux 7 là legacy; nếu không có endpoint scanner còn được hỗ trợ thì file delivery phải tiếp tục fail-closed.

### Windows Server 2025

Với agent đã enroll, cập nhật script/requirements rồi restart Scheduled Task:

```powershell
Copy-Item -Force .\agent\tram_agent.py "$env:ProgramFiles\TramVanHanhAgent\tram_agent.py"
& "$env:ProgramFiles\TramVanHanhAgent\venv\Scripts\python.exe" -m pip install --no-cache-dir -r .\agent\requirements.txt
Stop-ScheduledTask -TaskName TramVanHanhAgent -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName TramVanHanhAgent
Get-Content "$env:ProgramData\TramVanHanh\agent.log" -Tail 100
```

Microsoft Defender phải running. RDP phải được bật cục bộ và gắn certificate để agent thu thập `SSLCertificateSHA1Hash`; không cần mở firewall `3389` cho control plane.

## Thứ tự kiểm thử end-to-end

1. Xác nhận một agent Ubuntu `0.3.0` online và `tunnelOnline=true`.
2. Mở SSH từ dashboard, kiểm tra thao tác và recording; nếu lỗi lấy cùng lúc log `api`, `caddy`, `guacamole`, `guacd` và journal agent.
3. Xác nhận `guacd` không còn cần route trực tiếp tới IP máy Ubuntu trên port 22.
4. Xác nhận một Windows agent gửi RDP certificate fingerprint, sau đó mở RDP và kiểm tra recording.
5. Upload một file văn bản sạch, dùng admin khác duyệt job, xác nhận file vào inbox và ciphertext bị xóa.
6. Test EICAR trong staging: ClamAV trung tâm phải block, không tạo payload/job giao file.
7. Tắt ClamAV/Defender trong staging: file transfer phải fail-closed.
8. Test file trùng tên, traversal, Windows device name và file quá 50 MiB: đều phải bị từ chối.
9. Chỉ sau khi SSH/RDP tunnel đã chạy ổn mới đóng inbound `22/3389` từ mạng thông thường; nếu cần break-glass, chỉ mở từ bastion riêng có MFA.

## Bộ kiểm thử đã chạy tại commit `3941392`

- Control plane: `13/13` pass.
- Agent security: `4/4` pass.
- Rendered HTML: `2/2` pass.
- ESLint: pass.
- Vinext production build: pass.
- Python `py_compile`: pass.
- Ba file Compose parse YAML: pass.
- `git diff --check`: pass.

Docker/Caddy chưa được chạy end-to-end trên máy Windows phát triển vì máy này không có Docker/Caddy. Bắt buộc validate Compose và Caddy trên Ubuntu bằng lệnh triển khai ở trên trước khi đóng firewall trực tiếp.

## Ưu tiên sau khi smoke test tunnel/file

1. Tích hợp vault/LAPS cho credential SSH/RDP; hiện credential chỉ tồn tại trong token Guacamole ngắn hạn nhưng vẫn do người vận hành nhập.
2. Đưa recording và audit ra immutable/WORM storage, có quota, retention và legal hold.
3. Thay in-memory `TunnelHub` bằng broker phân tán trước khi scale API.
4. Bổ sung certificate lifecycle: revoke/CRL/OCSP và rotate tự động trước hạn.
5. Tích hợp EDR/WDAC/AppLocker/SELinux và network micro-segmentation. Antivirus không thể bảo đảm tuyệt đối trước zero-day hoặc khi control plane đã bị chiếm toàn quyền.
6. Pentest độc lập các luồng enrollment, WebSocket tunnel, Guacamole token, file approval và endpoint inbox trước production.

## Nguyên tắc không được phá vỡ

- Không thêm `command.run`, shell/PowerShell tùy ý hoặc destination tunnel tùy ý.
- Không bỏ mTLS, chữ ký request, TLS hostname verification, host-key/certificate pinning, RBAC, bốn mắt hoặc audit để sửa lỗi tạm.
- Không log/commit `.env`, password, token, private key, DB URL có password hoặc recording.
- Không cho file tự chạy và không bật lại clipboard/SFTP/RDP drive như đường truyền file phụ.
- Không public ClamAV, guacd, PostgreSQL hoặc relay port.
- Không xóa PostgreSQL/recording/volume để khắc phục sự cố nếu chưa có xác nhận rõ ràng.

Khi hoàn thành thay đổi tiếp theo:

```bash
git status -sb
git diff --check
# chạy test liên quan
git add -- <đúng file liên quan>
git commit -m "Mô tả ngắn"
git push origin main
git ls-remote origin refs/heads/main
```
