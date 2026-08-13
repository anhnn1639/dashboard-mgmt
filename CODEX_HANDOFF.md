# Bàn giao Codex — 14/08/2026

## Mục tiêu

Tiếp tục hoàn thiện hệ thống quản trị máy chủ tại repository:

```text
https://github.com/anhnn1639/dashboard-mgmt.git
```

Người dùng yêu cầu mỗi thay đổi hoàn chỉnh phải được commit và push trực tiếp lên nhánh `main`. Không tạo PR trừ khi người dùng thay đổi yêu cầu.

## Trạng thái Git hiện tại

- Nhánh: `main`
- Commit ứng dụng mới nhất trước tài liệu bàn giao: `96c680e Sign agent API requests`
- Agent mới nhất: `0.2.4`
- Commit tính năng lớn: `87501c7 Add contextual server management and secure access`
- GitHub CLI trên máy ở nhà báo token cũ không hợp lệ, nhưng xác thực Git remote vẫn push được bình thường.

## Việc đầu tiên cần làm tại công ty

```bash
git status -sb
git pull --ff-only origin main
git log -5 --oneline
```

Nếu có local changes thì phải đọc diff trước. Không dùng `git reset --hard` và không xóa thay đổi chưa xác định của người dùng.

Sau đó đọc toàn bộ file này và kiểm tra commit hiện tại có chứa `96c680e` hoặc commit mới hơn.

## Trạng thái máy Ubuntu đang test

Máy Ubuntu đã chạy agent nhưng log cuối cùng vẫn thuộc agent `0.2.3` và API/Caddy trước commit `96c680e`:

```text
401 Unauthorized (... mTLS client certificate required)
```

Nguyên nhân: Caddy đã chấp nhận mTLS nhưng placeholder chứng thư không được đưa vào header upstream như dự kiến. Commit `96c680e` đã loại bỏ phụ thuộc này:

- Caddy vẫn bắt buộc và xác minh mTLS trên cổng `9443`.
- Agent tự ký từng request bằng private key hiện có.
- API xác minh certificate fingerprint, CN, timestamp, nội dung và chữ ký ECDSA.
- Không cần tạo token hoặc enroll lại nếu certificate/key hiện tại còn khớp database.

## Lệnh triển khai bắt buộc tiếp theo trên Ubuntu

Đang chạy bản test với PostgreSQL trong Docker:

```bash
cd /home/ubuntu/dashboard-mgmt
git pull --ff-only origin main

docker compose -f compose.yaml -f compose.test.yaml up -d --build api
docker compose -f compose.yaml -f compose.test.yaml restart caddy

cp agent/tram_agent.py /opt/tram-agent/tram_agent.py
systemctl restart tram-agent

sleep 10
systemctl status tram-agent --no-pager
journalctl -u tram-agent -n 80 --no-pager
docker compose -f compose.yaml -f compose.test.yaml logs --tail=100 api caddy
```

Kết quả mong đợi:

- `tram-agent.service` là `active (running)`.
- Log không còn `401 Unauthorized`.
- Dashboard hiển thị agent version `0.2.4` và `last seen` mới.
- CPU, RAM, disk, uptime và inventory được cập nhật.

Nếu log báo timestamp ngoài cửa sổ cho phép, đồng bộ giờ hệ thống trước:

```bash
timedatectl status
timedatectl set-ntp true
systemctl restart tram-agent
```

Nếu vẫn lỗi, thu thập nguyên văn các kết quả sau rồi sửa theo lỗi thực tế:

```bash
journalctl -u tram-agent -n 100 --no-pager
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api caddy
docker compose -f compose.yaml -f compose.test.yaml ps
```

Không in nội dung private key, `.env`, mật khẩu hay enrollment token vào chat/log.

## Cảnh báo `Errno 97`

Ubuntu hiện báo:

```text
psutil cannot enumerate network interfaces: [Errno 97] Address family not supported by protocol
```

Đây không còn là lỗi làm agent dừng. Agent `0.2.2+` tự chuyển sang `/usr/sbin/ip`, sau đó vẫn thu thập inventory. Có thể giảm mức log sau khi hệ thống hoạt động ổn, nhưng không bỏ fallback.

## Kiểm thử đã chạy

Tại commit `96c680e`, bộ test control plane đạt `5/5`:

```bash
cd control-plane
../.venv/Scripts/python.exe -m unittest discover -s tests -v
```

Các trường hợp đã kiểm tra gồm login + MFA, phân loại Windows/Linux, enroll, signed check-in, rotate certificate, từ chối certificate cũ và chấp nhận certificate mới.

Trên Linux có thể dùng Python/venv tương ứng thay cho đường dẫn Windows.

## Database và cách chạy

Toàn bộ dữ liệu bền vững phải lưu PostgreSQL.

- Test có PostgreSQL trong Docker:

  ```bash
  docker compose -f compose.yaml -f compose.test.yaml up -d --build
  ```

- Production dùng PostgreSQL bên ngoài:

  ```bash
  docker compose -f compose.yaml -f compose.external.yaml up -d --build
  ```

- Khi database/chưa cấu hình/chưa có admin, website phải mở setup wizard để nhập kết nối PostgreSQL, tạo admin local và đặt dashboard URL.
- Không commit thông tin kết nối thật hoặc mật khẩu database.

## Quy ước giao thức

- Dashboard, API công khai và Guacamole trên web: HTTP theo yêu cầu người dùng (`http://ops.example.com`).
- Agent control channel: HTTPS/mTLS tại `https://ops.example.com:9443`.
- Không chuyển cổng agent `9443` sang HTTP vì đây là kênh điều khiển đặc quyền.

## Các yêu cầu người dùng cần kiểm tra tiếp

Commit `87501c7` đã thêm phần lớn khung tính năng dưới đây, nhưng phải kiểm thử end-to-end trên máy thật trước khi coi là hoàn thành:

1. Bỏ nút “Tạo công việc” chung; mọi thao tác phải bắt đầu từ máy chủ đang được chọn.
2. Trang chi tiết máy chủ phải lấy dữ liệu thật và cho phép các thao tác phù hợp hệ điều hành:
   - tạo/khóa/mở khóa/xóa user, đổi mật khẩu;
   - tạo/xóa group, liệt kê group trên đúng máy được chọn, thêm/bỏ user khỏi group;
   - xem service/process/log/network;
   - thêm/xóa rule firewall;
   - quét/cài security updates;
   - extend volume Windows;
   - extend LVM/local volume Ubuntu/Linux;
   - reboot có kiểm soát và nhật ký kiểm toán.
3. Thanh tìm kiếm toàn cục phải gợi ý máy chủ thật, hỗ trợ hostname/IP/tag và mở đúng máy được chọn.
4. Kết nối SSH/RDP qua Guacamole phải hoạt động. Trước đây màn hình báo `An internal error has occurred within the Guacamole server`; cần retest sau khi agent online và xem log `guacamole`, `guacd`, `api` nếu còn lỗi.
5. Recording session:
   - độ phân giải cao nhất hợp lý;
   - dung lượng thấp nhất có thể;
   - production mount `RECORDING_DIR` ra thư mục bên ngoài container;
   - Audit phải có tab xem lại recording và kiểm soát quyền truy cập;
   - kiểm tra retention/dung lượng, không để đầy filesystem.
6. LDAP/Active Directory:
   - trang cấu hình kết nối và test bind/search;
   - login có hai tab `Local` và `Domain Login`;
   - ánh xạ group/domain role an toàn;
   - không log hoặc trả lại bind password.
7. MFA:
   - mọi user local/domain lần đầu login phải enroll TOTP bằng QR;
   - các lần sau bắt buộc MFA;
   - chống dùng lại cùng mã TOTP và audit đầy đủ.
8. Font giao diện đã được tăng kích thước trước đây; tiếp tục kiểm tra trên màn hình người dùng để bảo đảm tất cả trang đều đủ lớn.
9. Kiểm tra metrics/inventory sau khi agent `0.2.4` online; trước đây dashboard hiển thị CPU/RAM/disk bằng `0%` vì check-in bị lỗi.

## Ưu tiên xử lý ngày mai

1. Deploy commit `96c680e` theo lệnh ở trên.
2. Xác nhận agent `0.2.4` check-in và metrics/inventory có dữ liệu thật.
3. Chọn một máy Ubuntu và kiểm thử các tab chi tiết + một tác vụ an toàn như `service.list` hoặc `user.list`.
4. Kiểm thử SSH Guacamole; nếu lỗi, lấy log ba service và sửa nguyên nhân.
5. Kiểm thử global search suggestion.
6. Kiểm thử recording + playback với `RECORDING_DIR` nằm ngoài container.
7. Kiểm thử LDAP và luồng MFA bằng tài khoản test, không dùng tài khoản production đặc quyền trước.

## Nguyên tắc bảo mật khi làm tiếp

- Không cho phép command tùy ý từ UI; chỉ dùng action allowlist và validate chặt parameters.
- Tác vụ thay đổi hệ thống phải có lý do, quyền phù hợp, approval khi cần và audit.
- Không lưu mật khẩu SSH/RDP, LDAP hoặc token dạng rõ trong PostgreSQL/audit log.
- Không bỏ kiểm tra mTLS hoặc chữ ký request để “chạy tạm”.
- Không tắt xác minh TLS của agent.
- Không xóa dữ liệu PostgreSQL/recording/volume để sửa lỗi nếu chưa được người dùng cho phép rõ ràng.

## Khi hoàn thành một thay đổi

```bash
git status -sb
git diff --check
# chạy test liên quan
git add -- <chỉ các file liên quan>
git commit -m "Mô tả ngắn"
git push origin main
git ls-remote origin refs/heads/main
```

Sau đó cập nhật file bàn giao này nếu trạng thái triển khai hoặc lỗi đang theo dõi đã thay đổi.

