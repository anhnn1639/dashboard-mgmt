# Bàn giao Codex — 20/08/2026

## Repository và trạng thái

- Repository: `https://github.com/anhnn1639/dashboard-mgmt.git`
- Nhánh triển khai: `main`; người dùng cho phép commit/push trực tiếp thay đổi hoàn chỉnh.
- Thay đổi Nginx/port 3000 và Agent 0.4.1: `73bbc4b Run dashboard behind Nginx on port 3000`; MSI đã bundle vào main tại `3df6d06`.
- Đồng bộ `.env`/Nginx và version contract: `a38d722 Synchronize runtime config and release version`; MSI đồng bộ đã bundle tại `b7fada2`.
- Agent source đã tăng lên `0.8.9` cho cấu hình nguồn cập nhật; Linux executable và Windows MSI trong repository vẫn là `0.8.8` trong lúc chờ GitHub Actions build source commit mới. Chỉ đổi dòng này sang "đã đồng bộ/bundle" sau khi tải và kiểm tra artifact 0.8.9. Gói Linux vẫn self-contained, không cài Python/pip hoặc tải dependency lúc cài; unit systemd giữ `AF_NETLINK`.
- Log RDP ngày 17/08 xác nhận tunnel Agent, relay API và listener `127.0.0.1:3389` đều hoạt động; `guacd` dừng tại `Certificate validation failed`. Nguyên nhân là API gửi pin SHA-1 dạng compact trong khi FreeRDP 2.x của image `guacd` so sánh dạng colon-separated. API hiện chuẩn hóa pin thành `sha1:aa:bb:...`/`sha256:aa:bb:...`, tương thích cả FreeRDP 2.x và 3.x, vẫn giữ `ignore-cert=false`.
- Bản sửa mới nhất tách đúng label/input của form **Bộ cài Agent**, hiển thị lỗi màu đỏ, công khai trạng thái `agentTlsCaAvailable` và thay luồng export CA một lần bằng sidecar đồng bộ liên tục.
- Dashboard mở máy chủ bằng URL hash riêng và workspace toàn màn hình; breadcrumb quay lại đúng danh sách Linux/Windows. Các tab Tổng quan, Disk, Services, Tài khoản, Firewall, Tiến trình, Cập nhật, Truyền file và Nhật ký dùng trực tiếp action allowlist, dữ liệu quét từ đúng Agent đang quản trị và không có form command tùy ý.
- Dashboard 0.8.8 sửa form đăng nhập theo `dvh`, co gọn trên màn hình thấp và cuộn bên trong card khi thật sự cần; nút đăng nhập/MFA không còn bị cắt khỏi viewport. Ô OTP là input điều khiển chỉ nhận 6 chữ số, tự rỗng/focus khi sang bước MFA và có autofill sink ẩn để trình quản lý mật khẩu không chèn username vào ô OTP. Overview lấy sáu audit event mới nhất thật từ PostgreSQL khi role có `audit.view`. Process realtime 5 giây chỉ cập nhật số liệu, không chớp banner queued/dispatched; lỗi job thật vẫn hiển thị.
- Biểu đồ **Sức khỏe hạ tầng** dùng trực tiếp health hiện tại của fleet để tính ba tỷ lệ Ổn định/Cảnh báo/Nguy cấp hoặc mất kết nối; làm tròn theo largest-remainder nên tổng luôn đúng 100%, còn trường hợp chưa có máy được hiển thị như không có dữ liệu. Nhãn 24 giờ và 7 ngày không có dữ liệu lịch sử đã bị bỏ. Header hiển thị đồng hồ local của máy quản trị và cập nhật từng giây, tự chọn giao diện sáng 06:00–17:59 và tối ngoài khung giờ đó; palette sáng ghi đè đầy đủ panel/form/bảng/modal/sidebar để chữ và control luôn đủ tương phản.
- Bản vá tương phản giao diện sáng áp dụng một lớp màu chữ an toàn cho toàn bộ heading, nội dung, bảng, form, nút và modal để mọi màu trắng/sáng cũ đều trở về màu mực tối; sau đó áp lại màu ngữ nghĩa đủ tương phản cho link/IP, trạng thái tốt/cảnh báo/lỗi. Các thẻ chọn thành viên Local/LDAP, máy đích của task chung, nhãn trạng thái online/offline, nút thao tác Disk và phím tắt tìm kiếm đều có nền/chữ riêng cho light theme, không còn chữ tối trên thẻ nền tối. Hostname trong bảng Công việc dùng chữ đậm tối, IP dùng xanh; riêng log, kết quả lệnh và màn hình recording vẫn giữ nền tối/chữ sáng có chủ đích.
- Truyền file 0.8.8 sửa lỗi React mất `currentTarget` sau `await` gây toast `Cannot read properties of null (reading 'reset')`. Trần file đồng bộ lên 1 GiB ở UI/Nginx/Caddy/API/ClamAV/Agent. API không giữ nguyên file trong RAM: multipart spool ở thư mục riêng, quét ClamAV bằng stream, mã hóa AES-GCM theo khối 8 MiB vào bảng PostgreSQL `file_transfer_chunks`, rồi giải mã/stream tuần tự xuống Agent; hash/kích thước toàn file vẫn được Agent kiểm tra và payload bị xóa sau kết quả hoặc TTL 24 giờ.
- Dashboard hiển thị tên thao tác tiếng Việt trong Công việc, Hoạt động gần đây và Nhật ký kiểm toán; mã action kỹ thuật chỉ còn ở tooltip để tra cứu. Toàn trang bỏ `zoom: 1.2`, sidebar bám đúng `100dvh`, menu có vùng cuộn riêng khi màn hình thấp và thẻ bảo mật/tài khoản luôn nằm trong viewport.
- Trang **Công việc** có thanh tìm kiếm theo từ/cụm từ tiếng Việt hoặc English, action dễ đọc/mã gốc, lý do, hostname, IP, rủi ro, trạng thái và thời gian. Trang **Nhật ký kiểm toán** lọc tức thời trên 500 dòng đang tải theo cùng cơ chế, gồm cả nhãn action/kết quả đã dịch; chuẩn hóa Unicode nên tìm có dấu hoặc không dấu đều khớp. Các chú giải giao diện không còn công khai tên sản phẩm lưu trữ, reverse proxy, framework, scanner hay dịch vụ truy cập từ xa; màn hình thiết lập và lỗi vận hành dùng thuật ngữ chức năng chung, còn dữ liệu kỹ thuật vẫn được giữ ở backend phục vụ vận hành/audit.
- Toàn bộ 232 khai báo `font-size` của dashboard đã tăng tổng cộng `3px` so với thiết kế gốc qua biến CSS dùng chung; không dùng `zoom` và không scale kích thước khung/nút/bảng. Sidebar desktop kéo ngang được từ 190–420px hoặc chỉnh bằng phím mũi tên/Home/End; menu tự xuống dòng khi hẹp và trở lại một dòng khi đủ rộng, trong khi mobile giữ sidebar 66px cố định.
- Công việc vận hành hiển thị máy chủ theo `hostname [IP]` thay cho 8 ký tự UUID. Hostname màu trắng/in đậm, IP màu xanh da trời/chữ thường và có khoảng cách 7px; hai phần tự wrap khi cột hẹp. API trả identity từ bản ghi Server đã qua kiểm tra visibility; dashboard còn đối chiếu `serverId` với chính fleet đang tải để vẫn hiện tên/IP thật khi API Công việc cũ chưa được recreate. Danh sách Linux/Windows dùng nút **Delete** màu đỏ, có vùng bấm rõ ràng; modal gõ `DELETE`, RBAC, audit và cơ chế retire certificate vẫn giữ nguyên.
- Khu vực tài khoản cuối sidebar mở modal tự phục vụ thay vì đăng xuất ngay. User Local tự đổi tên hiển thị và mật khẩu sau khi xác minh mật khẩu hiện tại; username/role chỉ đọc, còn thông tin và mật khẩu LDAP tiếp tục do Active Directory quản lý. Administrator có nút **Reset MFA** trong giao diện sửa user; API xóa credential TOTP cũ, ghi audit và bắt buộc user quét QR mới ở lần đăng nhập sau. Role khác bị chặn ở backend kể cả có quyền quản lý user tùy chỉnh.
- Bản xử lý báo cáo ANTT 20/08 chuyển browser session sang cookie `Secure`/`HttpOnly`/`SameSite=Strict`, không còn access token trong `sessionStorage`; JWT mặc định 60 phút và có `jti`. Logout ghi `jti` vào bảng PostgreSQL `revoked_session_tokens`, nên replay Bearer/cookie cũ bị trả `401`; API/CLI vẫn dùng được Bearer token. Mọi token phát trước bản này không có `jti` và sẽ buộc đăng nhập lại sau deploy.
- Cùng bản ANTT, mọi `403` của user đã xác thực được audit thành `security.authorization.denied`; trang Nhật ký kiểm toán có tìm kiếm/lọc action/kết quả. LDAP plaintext bị từ chối và UI chỉ cho LDAPS xác minh certificate. Quyền `logs.configure` tách khỏi `logs.view`, Auditor/Viewer không còn sửa nguồn log; catalog role không còn công khai cho role thông thường. Nginx ẩn header upstream `Server`; CSP chặn script attribute và nâng cấp mixed content. Vinext hiện vẫn cần inline hydration/style, nên `unsafe-inline` cùng origin còn là ngoại lệ kỹ thuật mức thấp cần chuyển sang nonce/hash ở đợt framework tiếp theo.
- Lỗi SSH Guacamole ngày 16/08 đã xác định ở lớp Docker DNS, trước tunnel/sshd: container `guacamole` và `guacd` cùng network `tram-van-hanh_session` nhưng endpoint cũ có `Aliases=null`, nên `getent hosts guacd` rỗng và Tomcat báo `UnknownHostException: guacd`. Compose hiện khai báo alias `guacd`/`guacamole` tường minh và chỉ khởi động Guacamole sau khi `guacd` healthy.
- Sau khi DNS chạy, log `guacd` xác nhận hai lỗi kế tiếp: host key bị pin cho `tunnel-relay` nhưng thiếu cổng relay động (`Host key does not match known hosts entry`) và recording/typescript bị `Permission denied`. API hiện sinh known_hosts dạng `[tunnel-relay]:PORT KEY_TYPE KEY`; recording-init dùng đúng owner guacd `1000`, shared GID cấu hình bằng `RECORDING_GID`, còn API/Guacamole chỉ được thêm nhóm để đọc. Log phiên mới ngày 16/08 cho thấy recording đã chạy nhưng host key vẫn mismatch: nguyên nhân cuối là agent 0.4.1 luôn gửi ED25519 trong khi libssh2 của guacd ưu tiên/đàm phán ECDSA P-256 trước. Agent 0.4.2 chọn ECDSA, rồi ED25519, rồi RSA theo đúng thứ tự tương thích với guacd.
- Sau Agent 0.4.2, API đã mở được relay nhưng trình duyệt rơi về trang danh sách Guacamole và `guacd` không nhận connection. Nguyên nhân là URL launch chỉ trỏ `/guacamole/?data=...` thay vì route client. API hiện trả thẳng `/guacamole/#/client/BASE64URL?data=...`, trong đó identifier là `CONNECTION_NAME\0c\0json` và encrypted JSON được percent-encode toàn bộ.
- Route client đúng nhưng Guacamole vẫn có thể báo `The requested connection does not exist` nếu cùng origin còn `GUAC_AUTH_TOKEN` từ lần đăng nhập Guacamole trước/manual. Token cũ được gửi cùng encrypted JSON và được ưu tiên, nên data source `json` không có trong session hiện tại. Dashboard hiện xóa riêng `GUAC_AUTH_TOKEN` trong localStorage sau khi API tạo relay và trước khi điều hướng; session dashboard nằm trong cookie `HttpOnly` riêng nên không bị ảnh hưởng.
- API có lịch sử job theo từng máy chủ và chỉ trả output cho role được phép xem action đó; kết quả `inventory.collect` hợp lệ cập nhật inventory bền vững trong PostgreSQL.
- Tab **Firewall** đã bỏ form tác vụ chung, thay bằng bảng tất cả rule của backend đang quản lý firewall, checkbox chọn một/nhiều dòng, nút `+` mở form theo Windows/Linux và nút `−` mở danh sách xác nhận từng dòng. Nút Delete chỉ xuất hiện sau khi gõ đúng `CONFIRM`; add/remove được xếp hàng trực tiếp, vẫn kiểm tra RBAC/MFA và ghi audit trong PostgreSQL.
- Agent 0.5.0 chuẩn hóa Windows Defender Firewall, firewalld (Red Hat/CentOS), UFW (Ubuntu), nftables và iptables/ip6tables. Xóa dùng định danh gốc an toàn: Windows `Name`, UFW number theo thứ tự giảm dần, firewalld zone/type/value, nft handle và iptables chain index; không nhận command/script tùy ý.
- Agent 0.6.0 và dashboard cho kéo-thả thứ tự UFW, nftables và iptables trong đúng IP family/table/chain. Reorder là job `critical` được xếp hàng trực tiếp; agent đối chiếu lại ID/nội dung snapshot trước khi đổi. UFW dùng insert + delete với rollback, nftables dùng một JSON transaction, iptables dùng save/restore. Windows không bật kéo vì Microsoft không hỗ trợ administrator-assigned ordering và Block xung đột ưu tiên hơn Allow; firewalld chưa bật kéo vì thứ tự thực thi phụ thuộc rich-rule priority và các chain action.
- Firewall scan không còn fail khi nftables có ruleset rỗng hoặc máy chưa có backend được hỗ trợ; UI hiển thị warning cho trạng thái không có backend và hiển thị nguyên văn output của job nếu agent thực sự trả `failed`, kèm phiên bản agent để chẩn đoán.
- Agent 0.6.1 fallback sang `iptables -S`/`ip6tables -S` trên các table chuẩn khi thiếu hoặc lỗi `iptables-save`; đây là bản sửa cho host vẫn thấy rule bằng `iptables -L` nhưng dashboard báo không có backend. Reorder cũng fallback sang insert/delete native có stale guard và rollback. Rule hạ tầng Docker vẫn được liệt kê nhưng bị khóa xóa/kéo ở UI và bị agent từ chối nếu cố thao tác trực tiếp.
- Agent 0.6.2 không còn phụ thuộc PATH của service khi tìm `firewall-cmd`, `ufw`, `nft`, `iptables` và các helper save/restore: sau `shutil.which` sẽ dò allowlist `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`. Nếu vẫn không có backend, output job chứa chẩn đoán theo IPv4/IPv6 và UI hiển thị kèm chính xác agent version để lần kiểm tra tiếp theo không còn cảnh báo mơ hồ.
- Chẩn đoán Agent 0.6.2 trên host test xác nhận nguyên nhân thật: `iptables-nft`, `ip6tables` và psutil đều lỗi `Address family not supported by protocol` chỉ khi chạy trong service, còn shell root dùng `iptables -L` bình thường. Unit cũ giới hạn `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, làm nftables/iptables-nft và đọc interface không mở được netlink socket. Agent 0.6.3 thêm đúng `AF_NETLINK`, không gỡ các giới hạn systemd còn lại.
- Agent 0.6.4 trả thêm capabilities lấy trực tiếp từ máy đang quản trị: Windows Firewall profile và profile đang bật; toàn bộ firewalld zone/default zone; nftables base chain `type=filter` có hook input/output; iptables/ip6tables chain INPUT/OUTPUT của table filter. Dashboard dùng select từ metadata này, không còn bắt nhập tay table/chain và không đưa NAT/DOCKER vào mục tiêu thêm rule.
- Modal thêm rule 0.6.4 tách header/body/footer, body cuộn độc lập và tính kích thước theo lớp phủ để vẫn nằm trong viewport khi dashboard dùng zoom 1.2. Form đổi theo backend Windows/UFW/firewalld/nftables/iptables, có preset SSH/HTTP/HTTPS/DNS/RDP, giải thích zone khác chain, preview rule, gợi ý CIDR và tự đổi nhãn inbound/outbound.
- API và Agent 0.6.4 validate lại backend-specific scope. Ngay trước khi chạy, Agent đọc lại zone hoặc filter chain để chặn metadata stale; chỉ cho table filter/base chain input-output, kiểm tra CIDR đúng IPv4/IPv6 và giữ RBAC/MFA/audit.
- Modal thêm firewall đổi nút gửi thành **Thêm Rule** và hiển thị **Đang chờ quét firewall…** khi backend chưa sẵn sàng, tránh trường hợp bấm mà không có phản hồi. Rule hợp lệ được xếp hàng trực tiếp để Agent nhận.
- Sau nâng cấp agent, job firewall `failed` cũ vẫn còn bền vững trong PostgreSQL. Dashboard hiện ghi rõ thời điểm của lỗi cũ và tự tạo một lần quét mới khi người dùng mở lại tab Firewall nếu job mới nhất đang `failed`; nút **Quét lại** luôn có thể tạo job thủ công.
- Agent 0.6.5 chèn rule mới lên vị trí đầu tiên trên các backend có thứ tự quản trị rõ ràng: UFW dùng `insert 1`, nftables dùng `insert rule`, iptables/ip6tables dùng `-I CHAIN 1`. Windows giữ semantics native (Block ưu tiên Allow) và firewalld giữ semantics zone/rich-rule priority, không giả lập một thứ tự không tồn tại.
- Sau mỗi kết quả thêm, xóa hoặc sắp xếp firewall — thành công hay thất bại — API tự tạo đúng một job `firewall.list`; kết quả gửi lặp không tạo thêm job quét. Dashboard polling nhận kết quả mới, đồng thời hiển thị rõ mutation đang chờ Agent, đang chạy hoặc đang quét lại.
- Theo yêu cầu mô hình một quản trị viên, toàn bộ job website và `file.deliver` hiện tạo thẳng ở trạng thái `queued`; endpoint `/api/v1/jobs/{id}/approve`, nút duyệt và policy approval đã bị loại bỏ. Job `pending_approval` từ bản cũ được đánh dấu `cancelled` khi API khởi động và payload file tương ứng bị xóa; quản trị viên phải tạo lại nếu vẫn cần. MFA, RBAC, allowlist/validation, audit và các kiểm tra tại Agent vẫn giữ nguyên.
- Ảnh test thực tế xác nhận `firewall.rule.add` đã tới Agent 0.6.5 nhưng nftables báo syntax error tại comment `TramOps - SSH ALLOW`: nft CLI ghép argv thành grammar nên comment có khoảng trắng phải mang dấu nháy literal. Agent 0.6.6 dùng JSON-compatible quoted/escaped string cho nft comment, vẫn gọi subprocess bằng argv và không qua shell; unit test bao phủ khoảng trắng, dấu nháy và backslash. API tiếp tục trả `exitCode`/`output` theo RBAC và UI hiển thị nguyên văn lỗi có vùng cuộn.
- Agent/dashboard 0.7.0 thay toàn bộ form thao tác chung ở các tab tài nguyên. **Disk** hiển thị cây Disk → partition → filesystem/LVM, dung lượng thực/unallocated/free/extendable; Windows dùng Storage cmdlet, Ubuntu dùng apt/systemd/parted/LVM, Red Hat và Oracle Linux dùng dnf/yum/systemd/parted/LVM. Modal tạo/extend/xóa chỉ nhận target/capacity Agent vừa quét, nằm trong viewport và cuộn nội bộ trên màn hình nhỏ. Boot/system/root bị khóa; layout được đối chiếu lại ngay trước thao tác; volume dữ liệu đang mount chỉ xóa sau khi unmount thành công và dòng UUID tương ứng được dọn khỏi fstab sau khi xóa thành công.
- Agent/dashboard 0.7.1 sửa hai lỗi Windows thực tế: Windows Update API duyệt `IUpdateCollection` bằng `Item(index)` và dùng tiêu chí `IsInstalled=0`, nên lấy cả update/driver đang chờ giống Windows Settings; tab Disk chuẩn hóa object/array đệ quy trước khi render, nên payload chỉ có một partition/volume không còn làm client crash khi mở cây.
- Agent/dashboard 0.7.2 xử lý dữ liệu Windows thực tế còn lại: Disk chỉ đưa scalar đã chuẩn hóa vào React nên object CIM/PowerShell không thể làm sập route khi bung partition; Windows Update quét đồng thời WUA và `root\ccm\ClientSDK/CCM_SoftwareUpdate`, hiển thị chẩn đoán từng nguồn và cài update ConfigMgr bằng `CCM_SoftwareUpdatesManager.InstallUpdates`. Firewall có tìm kiếm theo tên/ID/IP/cổng/profile/zone và lọc action, hướng, trạng thái, backend; chọn tất cả chỉ tác động các rule đang hiển thị.
- Agent/dashboard 0.7.3 xếp Windows partition theo offset thật, chèn các segment Unallocated vào đúng vị trí và hiển thị sơ đồ vật lý nên layout `C: → Recovery → 10 GiB Unallocated` không còn bị hiểu nhầm. Extend chỉ bật theo `SizeMax`; Shrink chỉ bật cho NTFS theo `SizeMin`, đọc lại live ngay trước `Resize-Partition`, tự quét Disk sau kết quả và khóa EFI/MSR/Recovery/OEM. Shrink chỉ tạo free space bên phải volume, không giả vờ di chuyển Recovery.
- Windows Update 0.7.3 thử WUA online theo nguồn Microsoft Update/WSUS đang cấu hình, rồi fallback `Online=false` để đọc cache cục bộ nếu online lỗi. Payload phân biệt rõ `ok/cached/error`, mã HRESULT, service wuauserv/BITS và ConfigMgr `not_installed`; UI không còn hiển thị `0 update` như một kết luận khi WUA timeout `0x80072EE2`, cũng không coi thiếu namespace ConfigMgr là lỗi.
- Agent/dashboard 0.7.4 đọc Windows Update cache trước bằng COM session độc lập để lấy đúng danh sách Windows Settings đã lưu ngay cả khi LocalSystem timeout nguồn online; chỉ quét online khi cache rỗng. Agent đánh thức `wuauserv`/BITS nếu service đang dừng nhưng không bị Disabled, ghi lại hành động trong diagnostics, và lúc cài cũng đối chiếu chính catalog cache rồi kiểm tra kết quả download trước khi install.
- Agent/dashboard 0.7.5 chạy job dài trong worker đơn tách khỏi vòng check-in nên Windows Update không còn chặn heartbeat/làm Agent trông như crash; check-in 10 giây chỉ dispatch một job, job đang chạy được báo về API và job bị gián đoạn do restart được requeue. Windows Update cache được dò thêm trên mọi WUA service đã đăng ký, giữ `ServiceID` để cài đúng nguồn và giới hạn lần quét online 180 giây. Tab Updates chỉ hiển thị patch, không còn hai card diagnostics WUA/ConfigMgr.
- Agent/dashboard 0.7.6 sửa modal LDAP theo đúng viewport kể cả khi dashboard đang dùng CSS zoom: header/footer cố định, body cuộn theo kích thước thực của overlay, có fallback `vh`/`dvh` và form tự rơi về một cột trên màn hình nhỏ. Danh sách Windows/Linux có checkbox và nút **Tạo task chung** để tạo user hoặc firewall rule cho tối đa 100 máy cùng OS. PostgreSQL lưu `bulk_tasks`/`bulk_task_items`, mỗi máy có job riêng, password chỉ tồn tại ở tham số job đã mã hóa; RBAC/MFA/allowlist/audit vẫn áp dụng.
- Agent/dashboard 0.8.0 thay installer Linux phụ thuộc pip bằng executable PyInstaller tự chứa runtime/dependency. Binary build bằng runtime đã pin checksum có baseline glibc 2.17 và đã chạy thành công trong container Ubuntu 22.04/24.04, Oracle Linux 7/8 và Red Hat UBI 7/8. Installer từ chối OS/architecture ngoài allowlist, không gọi `apt`, `dnf`, `yum` hoặc `pip`; OpenSSH/ClamAV là capability của hệ điều hành nên chỉ cảnh báo/fail-closed thay vì âm thầm tải từ Internet.
- Agent/API 0.8.1 sửa HTTP 500 khi bootstrap máy mới: audit actor `bootstrap:<UUID>` dài 46 ký tự trước đây bị ghi nhầm vào `jobs.created_by varchar(36)` khi xếp hàng quét ban đầu. PostgreSQL từ chối trong khi SQLite test không bắt lỗi. Job nay dùng đúng user UUID của quản trị viên đã tạo package; audit vẫn giữ actor có namespace. Lỗi HTTP bootstrap cũng được Agent in ngắn gọn cùng `detail`, không còn traceback PyInstaller khó hiểu. Sửa này áp dụng chung cho Windows, Ubuntu, Oracle Linux và Red Hat.
- Windows Update 0.8.1 cho full WUA scan tối đa 900 giây thay vì cắt cứng ở 180 giây; Microsoft không cam kết thời gian hoàn tất của WUA và scan đầu trên Server 2022/WSUS có thể vượt ba phút. Heartbeat chỉ đọc cache `Online=false` tối đa 30 giây nên scan chậm không làm Agent mất check-in. PowerShell progress bị tắt để không trả `#< CLIXML` vào job. Workflow Linux nay chạy `diagnose`/inventory thật trên cả sáu image, không chỉ `--help`; đường dẫn `lsblk`, `lvs`, `systemctl` được dò từ allowlist chuẩn thay vì hard-code.
- Agent/dashboard/API 0.8.2 thêm fallback `lsblk --pairs --bytes` cho util-linux 2.23 của Oracle Linux/RHEL 7 khi chưa có `--json`; cây disk/partition vẫn được dựng theo `PKNAME`. Process trả CPU%, RAM%, RSS theo mẫu 350 ms; UI mặc định refresh 5 giây, lọc process đang dùng CPU/RAM và sắp xếp tăng/giảm theo từng cột. Users & Groups có filter active/disabled, modal đổi mật khẩu/group/expiry/admin/enable-disable và unlock theo OS; built-in account vẫn bị bảo vệ.
- Windows Update 0.8.2 tách ConfigMgr, WUA cache, `DetectNow` và WUA online thành các PowerShell process có timeout độc lập. Kết quả cache/ConfigMgr không bị mất khi online WUA bị treo; timeout online được trả thành diagnostics và Agent đọc lại cache thay vì làm cả job `failed`.
- PostgreSQL 0.8.2 có platform group/membership, server user/group share và server retirement. Chỉ role `admin` thấy toàn bộ fleet và được share/xóa; user khác chỉ thấy server được gán trực tiếp hoặc qua group, kiểm tra lại ở API server/job/file/session/bulk chứ không chỉ ẩn UI. Xóa server là retire có audit: ẩn fleet, từ chối certificate Agent cũ và giữ lịch sử. LDAP cấu hình được tối đa 20 group DN, có nút quét group và login dùng AD matching-rule-in-chain cho cả membership trực tiếp/lồng nhau; role riêng của user LDAP vẫn giữ nguyên.
- Installer Linux 0.8.2 nhận diện đủ bộ identity hiện hữu (`agent.json`, certificate, private key và hai CA) trước khi dừng service. Khi chạy `.run` mới trên máy đã enroll, installer giữ nguyên identity, chỉ thay binary/unit rồi restart giống MSI Windows; không còn gọi bootstrap và nhận HTTP 409. Identity thiếu một phần bị chặn trước khi thay đổi service để tránh tự xóa khóa hoặc tạo máy trùng.
- Windows Update 0.8.3 đọc policy, WUA services, nguồn mặc định và thời điểm scan thành công trước khi quét. Agent buộc `ServerSelection=1` cho WSUS hoặc `ServerSelection=2` cho Windows Update public; policy nửa vời `WUServer` + `DoNotConnectToWindowsUpdateInternetLocations=1` nhưng thiếu `UseWUServer=1` bị báo ngay, không treo rồi kết luận sai 0 update. Cache chỉ được coi là hiện tại trong 15 phút; full scan có tối đa 900 giây và vẫn chạy ngoài heartbeat. Payload luôn phân biệt complete/fresh-cache/timeout/invalid-policy; UI giữ kết quả hoàn tất gần nhất, khóa cài từ dữ liệu cũ và hiển thị nguồn/lần scan/thông báo gọn. Agent cũng từ chối cài WUA khi lần đối chiếu mới chưa hoàn tất.
- Agent/dashboard 0.8.4 sửa resize theo semantics native. Windows tách bảo vệ xóa khỏi bảo vệ resize nên C: vẫn không thể xóa nhưng được Shrink/Extend như Disk Management; biểu thức `endOffsetBytes` được sửa để các segment Unallocated hiện đúng thứ tự, và nếu lần scan chưa đọc được `SizeMin` thì modal vẫn cho nhập để Agent đối chiếu live ngay trước `Resize-Partition`. Oracle Linux/RHEL 7 lấy partition table, số partition và offset chính xác từ `parted -m` khi `lsblk` cũ thiếu `--json/START/PARTN/PTTYPE`; `/dev/sda2` LVM PV có free tail liền kề được tăng bằng `resizepart` + `pvresize`, sau đó UI hiển thị riêng LV để chạy `lvextend --resizefs`. Root data được phép extend nhưng vẫn khóa xóa; boot/EFI/read-only tiếp tục khóa resize. Process realtime dùng timer bền qua vòng poll job và không xếp job mới khi mẫu trước còn chạy. QR MFA đổi sang `img data:` tương thích CSP cho cả Viewer. PowerShell CLIXML được rút thành lỗi đọc được; HRESULT `0x80072EE2` được giải thích là timeout nguồn WSUS/Windows Update thay vì đổ XML thô.
- Agent/dashboard/API 0.8.5 sửa trường hợp bố cục đã nhận đúng `C: → 10 GiB Unallocated → Recovery → 10 GiB Unallocated` nhưng Extend/Shrink vẫn bị khóa. Capacity Extend lấy trực tiếp segment Unallocated nằm ngay bên phải thay vì để `Get-PartitionSupportedSize` stale ghi đè; Extend và Shrink chạy DiskPart native (`extend`, `shrink desired/minimum`) giống Disk Management, chỉ nhận target allowlist, kiểm tra lại layout trước khi chạy và đối chiếu kích thước partition sau kết quả. Shrink NTFS có drive letter vẫn mở modal khi lần scan không trả được SizeMin; native Windows quyết định giới hạn thực tại thời điểm chạy.
- Agent 0.8.5 hỗ trợ tối đa bốn job đồng thời cho các tác vụ đọc; mutation vẫn khóa tuần tự và control plane chỉ dispatch tối đa một mutation để tránh các thay đổi hệ thống chạy đè nhau. Check-in của Agent mới là 5 giây, báo toàn bộ `active_job_ids`, giữ tương thích Agent cũ chỉ báo một job; process realtime, disk/log/update scan không còn phải đợi một job đọc dài hoàn tất. Nút **Làm mới** của danh sách Linux/Windows chỉ refetch `/api/v1/servers`, giữ nguyên route/tab/filter thay vì reload toàn trang.
- Banner Windows Update 0.8.5 giải thích rõ Windows Settings có thể vẫn hiển thị các gói đã phát hiện/tải/Pending install từ lần search cũ. Khi máy không có Internet và không tới WSUS, WUA online timeout là đúng; Agent không biến timeout thành kết luận 0 update và không cho cài danh sách chưa xác minh.
- Agent/dashboard 0.8.6 sửa lỗi `lvextend` trên cả Ubuntu và Oracle Linux khi số GiB thập phân đổi sang byte không chia hết cho sector 512. UI làm tròn xuống theo 512 byte trước khi gửi; Agent tiếp tục căn chỉnh và kiểm tra lại dung lượng VG live trước khi chạy `lvextend --resizefs`. Linux partition Extend căn theo logical sector của disk và tạo LV mới cũng căn 512 byte, nên không còn `Size is not a multiple of 512` hoặc `Invalid argument for --size`.
- Agent/dashboard/API 0.8.7 kiểm tra nhanh đúng nguồn trước khi chạy quét update dài. Windows phân biệt public Windows Update không có Internet với WSUS mất kết nối bằng probe tối đa 5 giây/endpoint, dùng system proxy/default credential của LocalSystem; host offline không còn chờ hết WUA timeout 900 giây. Ubuntu refresh metadata bằng APT với timeout/retry hữu hạn; Oracle Linux/RHEL dùng YUM/DNF refresh đúng repository của release, lỗi kết nối trả payload có cấu trúc thay vì làm job treo/failed mơ hồ. WUA vẫn dùng `IsInstalled=0 and IsHidden=0`, tức native applicability của đúng Windows host; Linux dùng source đang cấu hình cho đúng release/architecture. Tab Updates bỏ toàn bộ banner giải thích dài, chỉ giữ ba ô Nguồn/Lần quét hoặc OS version/Trạng thái và khóa cài từ scan chưa hoàn tất.
- Agent/dashboard/API 0.8.9 thêm nút **Nguồn cập nhật** theo từng server trong tab Cập nhật. Ubuntu 22.04/24.04 lưu bản gốc rồi chỉ vô hiệu source Ubuntu chuẩn, sinh `tram-os-default.sources` với đúng jammy/noble và giữ nguyên Docker/PPA/repo ứng dụng. Oracle Linux 7/8 chỉ tắt các repo `ol7_*`/`ol8_*` đang bật, sinh `tram-os-default.repo` giữ GPG/TLS metadata và không chạm EPEL/Docker/repo ứng dụng; chế độ mặc định khôi phục đúng trạng thái trước lần cấu hình đầu. Windows bật WSUS sẽ ghi đồng bộ WUServer/WUStatusServer/UseWUServer và chặn fallback Internet; tắt WSUS sẽ gỡ endpoint cục bộ và dùng Microsoft Update. URL bị giới hạn HTTP/HTTPS không credential/query/fragment; role cần `updates.manage`, mọi thay đổi có audit và tự tạo `patch.source.read` + `patch.scan` để hiển thị trạng thái thực tế.
- Nút **Tạo task chung** 0.8.7 mở modal ngay cả khi chưa tick trước máy chủ. Loại task mới **Cập nhật bản vá theo OS + version** đi qua hai bước: chọn nhóm OS/version và máy đích, sau đó chọn catalog patch chung của toàn bộ target. API chỉ chấp nhận các máy cùng OS/version/architecture, đối chiếu ID/version bằng scan hoàn tất mới nhất và ghim revision riêng của từng host trước khi tạo từng job `patch.install`; user/firewall bulk task cũ vẫn giữ. Thiết kế kho bản vá cho mạng cách ly nằm tại `PATCH_RELAY_ARCHITECTURE.md`: Windows dùng WSUS upstream/downstream hoặc export/import, Linux dùng APT/YUM/DNF mirror có chữ ký; không đẩy file tùy ý qua kênh Agent 9443.
- API 0.8.0 tắt hoàn toàn Swagger/ReDoc/OpenAPI (`/api/docs`, `/api/openapi.json`, `/api/redoc` đều 404), giảm setup status public xuống bốn trường không nhạy cảm và bắt buộc setup token tối thiểu 32 ký tự cho cài đặt mới. PostgreSQL lưu bộ đếm throttle đăng nhập/MFA theo IP và identity đã HMAC; API bật Trusted Host, no-store/nosniff/frame deny, còn Caddy bật CSP/HSTS/referrer policy và Nginx ẩn version.
- Route audit tự động xác nhận mọi browser API ngoài allowlist public đều phụ thuộc xác thực; route Agent tiếp tục dùng certificate/chữ ký/replay protection. Role Viewer đọc `/api/v1/me` rồi chỉ render các workspace được cấp quyền; URL hash admin cũ như `#/access` tự chuyển sang trang đầu tiên được phép nên không còn làm trang đen/crash. Dependency Python có advisory đã nâng lên FastAPI 0.141.1, Starlette 1.6.0, PyJWT 2.13.0, cryptography 50.0.0 và python-multipart 0.0.32.
- Firewall task chung dùng action allowlist `firewall.rule.add.auto`: Agent đọc backend trực tiếp ngay trước khi chạy rồi chọn Windows Firewall profile Any, UFW đang active, default firewalld zone hoặc filter INPUT/OUTPUT thật của nftables/iptables theo IP family. UI Linux giới hạn Inbound để tương thích firewalld zone; `deny` được ánh xạ đúng sang Block/Drop native thay vì sinh verdict nftables/firewalld không hợp lệ. Tạo user tự đọc Administrators theo SID trên Windows, `sudo` trên Ubuntu và `wheel` trên Oracle Linux/Red Hat, không nhận tên group đoán từ trình duyệt.
- Mỗi server mới enroll tự được xếp hàng một lượt quét inventory, Disk, Services, Users, Groups, Firewall, Processes, Network, log sources/500 dòng log và Updates. Job chạy tuần tự qua worker nhưng Agent vẫn heartbeat/tunnel bình thường; kết quả job gửi lặp là idempotent và không tạo auto-refresh trùng.
- Recording được dò theo UUID với hậu tố `-`, `.`, `_` hoặc file UUID trực tiếp, không còn khóa cứng vào một mẫu tên. API mount recording read-write nhưng chỉ xóa qua yêu cầu PostgreSQL: admin tạo yêu cầu không được tự duyệt, admin thứ hai claim yêu cầu rồi mới xóa cả graphical recording và typescript; toàn bộ request/approve/failure được audit. `recording-init` dùng directory mode `2770` để shared GID của API có thể thực thi xóa đã duyệt. File vốn chưa từng được guacd tạo ở phiên cũ không thể khôi phục và UI sẽ ghi rõ `Không tìm thấy file` thay vì chờ vô hạn.
- Bản sửa recording 20/08 bỏ quy tắc light theme từng áp nền tối lên mọi phần tử con của `.recording-screen`. Guacamole dùng nhiều lớp canvas trong suốt, nên quy tắc cũ làm lớp trên che kín hình SSH/RDP dù timeline vẫn chạy; nay chỉ khung phát giữ nền tối, canvas/layer giữ trong suốt. API cũng loại mọi biến thể `.typescript`, `.typescript.N` và `.typescript.N.timing` khỏi lựa chọn file phát hình, nhưng vẫn giữ chúng trong luồng xóa đã duyệt. Browser fixture nhiều lớp xác nhận nội dung canvas dưới hiển thị qua lớp trên trong suốt.
- API entrypoint nay đăng ký `RECORDING_GID` vào supplementary groups của user `ops` trước khi `gosu`; điều này ngăn `gosu` làm rơi GID mà Docker `group_add` đã cấp và sửa trường hợp file thật tồn tại trên host nhưng website báo không tìm thấy. API trả riêng trạng thái mount thiếu, permission denied, file rỗng và file chưa tồn tại để UI chỉ đúng nguyên nhân thay vì gộp thành một thông báo.
- Modal xóa recording nay giải thích rõ lý do/ticket tối thiểu 5 ký tự và từ `DELETE` đều bắt buộc, trả lỗi API/network ngay trong modal thay vì nút xám im lặng. Cấu hình retention recording mặc định bật 180 ngày, lưu trong PostgreSQL, dọn ngay khi lưu/API startup và mỗi 6 giờ; chỉ xóa file recording/typescript có UUID hợp lệ, đủ tuổi và không thuộc session đang ghi. Tác vụ hệ thống này không qua phê duyệt nhưng có audit và trạng thái lần chạy.
- Trang **Người dùng & vai trò** nay là bảng toàn chiều rộng với nút `+`/`-`, sửa user theo dòng, bánh răng cấu hình LDAP và trình quản lý role riêng. Local user đổi được tên hiển thị, role, trạng thái và mật khẩu; LDAP user đổi được role/trạng thái riêng nhưng cả UI lẫn API đều cấm đổi mật khẩu LDAP. Role mặc định chỉ áp dụng lúc LDAP user đăng nhập lần đầu, còn role đã gán riêng được giữ nguyên. PostgreSQL có bảng `platform_roles`, seed sẵn Administrator/Operator/Viewer/Auditor và cho tạo role tùy chỉnh theo 20 permission chức năng; API kiểm tra permission thật cho job, file, Agent, audit, recording, session, user, LDAP và role, không chỉ ẩn nút trên giao diện.
- LDAP/AD hiện đồng bộ chủ động toàn bộ user trực tiếp hoặc lồng nhau của các group được phép đăng nhập bằng AD matching-rule-in-chain và LDAP paging, tối đa 10.000 user mỗi lượt. Lưu cấu hình có group sẽ đồng bộ ngay; nút **Đồng bộ AD** cho phép chạy lại sau khi membership thay đổi. User mới nhận role mặc định, user AD đã có giữ nguyên role/trạng thái quản trị viên gán, danh sách gắn nhãn **AD** và modal cho chọn mọi role hiện có. Username AD được đối chiếu không phân biệt hoa thường; collision với tài khoản Local không bị tự chuyển nguồn và được trả trong thống kê/audit.
- Ảnh production ngày 18/08 vẫn là form User/LDAP cũ, nghĩa là server mới pull source nhưng chưa rebuild/recreate `dashboard` và `api`. Sau pull commit mới phải chạy `docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate dashboard api`; hard refresh trình duyệt rồi kiểm tra nút `+`, `−`, `Roles`, bánh răng LDAP và bảng user toàn chiều rộng.
- Tab **Services** chỉ liệt kê tên, trạng thái, start cùng OS và Start/Stop/Restart; có filter running/stopped/other. **Tài khoản** có Users/Groups, multi-select, tạo/xóa, đổi password/expiry/group/quyền sudo-wheel-Administrators; hiển thị mọi local user/group nhưng khóa built-in theo UID/GID/SID. **Tiến trình** chỉ hiển thị tên và đối chiếu PID/name/create-time trước khi kill. **Cập nhật** chỉ cài đúng các gói/version được chọn, không còn action update-all. **Nhật ký** lấy tối đa 500 dòng, cấu hình nguồn bền vững trong PostgreSQL, chỉ cho file thật dưới `/var/log` hoặc Windows Event Log đang bật và tô cả dòng error/warning.
- Sau mọi mutation Services/Users/Groups/Disk/Process/Updates, API tự tạo job quét lại tương ứng giống Firewall; dashboard polling hiển thị dữ liệu thật mới nhất. Các thao tác vẫn chạy trực tiếp không qua phê duyệt, nhưng giữ MFA, RBAC, allowlist, live stale-target guard và audit PostgreSQL.
- `agent/VERSION` là nguồn version chung cho runtime Agent, Linux bundle, API status và WiX MSI; workflow truyền giá trị này vào PyInstaller/WiX và test chống lệch version.
- Luôn đọc `AGENTS.md`, xem status/diff trước khi sửa; không reset/xóa local change chưa xác định.

## Zero-touch Agent đã triển khai

- Admin có trang **Bộ cài Agent** để xem/sửa origin HTTPS của control plane và tải Linux `.run` hoặc Windows `.msi`.
- API lấy URL từ PostgreSQL `system_settings.dashboard_url`; không hard-code `ops.example.com`. URL chỉ nhận origin HTTPS, admin phải mở dashboard qua chính hostname muốn lưu.
- Khi đổi domain mà đã có agent, UI/API bắt buộc xác nhận vì agent cũ vẫn giữ endpoint và CA cũ.
- Mỗi bộ cài có claim ngẫu nhiên 256-bit, hết hạn 5–60 phút, dùng một lần và khóa theo `windows|linux`. Replay, claim hết hạn hoặc nhầm OS đều fail-closed/audit.
- Private key P-256 và CSR được sinh tại endpoint. Bộ cài chỉ mang locator, SHA-256 pin của CA và claim ngắn hạn; không chứa client private key/certificate dài hạn.
- Linux `.run` tự giải nén executable self-contained và unit systemd, enroll, xóa bootstrap secret rồi start service; không cài dependency/Python/pip hoặc tự tải ClamAV từ Internet. Thiếu ClamAV chỉ cảnh báo và file delivery giữ fail-closed.
- Windows dùng MSI generic; API không sửa bytes MSI mà chỉ phát nó dưới tên chứa locator/claim/CA pin, nên có thể giữ chữ ký Authenticode. Không được đổi tên file trước khi cài.
- MSI cài executable PyInstaller độc lập; Windows Server không cần Python. Service `TramVanHanhAgent` chạy `LocalSystem`, `Automatic`, phụ thuộc TCP/IP, start lúc cài và restart sau 30 giây nếu lỗi.
- `agent/install-windows.ps1` thủ công cũng đã chuyển từ Scheduled Task sang Windows Service.
- Windows/Linux vẫn tự vào đúng mục dựa trên inventory thực tế; server từ MSI Linux không thể dùng claim Windows và ngược lại.
- Khi đặt `WEB_TLS_TRUST=system`, bộ cài bootstrap qua certificate public của Nginx trên `443`; response enrollment vẫn cấp CA riêng để mọi lưu lượng Agent sau đó dùng mTLS trực tiếp trên `9443`.

## MSI artifact

- File: `agent/windows/TramVanHanhAgent.msi`
- Kích thước: `14,450,688` bytes.
- Phiên bản MSI: `0.8.8`.
- SHA-256: `D648979D37E6A774A07133760DC3F6F9FC7C426719152A74CBE878D53044BD93`.
- Build PyInstaller + WiX và upload artifact thành công từ source commit `73d08f7e31cc2726990b1a7ad1b18c89a34c4a06` trên GitHub Actions run `32325161405`; ProductVersion `0.8.8`, kích thước và SHA-256 ở trên đã được kiểm tra trực tiếp sau khi tải artifact bằng GitHub CLI.
- Workflow: `.github/workflows/build-agent-msi.yml`.
- Workflow hỗ trợ ký EXE và MSI nếu repository có secrets:
  - `WINDOWS_SIGNING_PFX_BASE64`
  - `WINDOWS_SIGNING_PASSWORD`
- Artifact hiện tại **chưa ký Authenticode** vì chưa có code-signing certificate. Trước production phải ký lại, thay MSI trong repo, kiểm tra `Get-AuthenticodeSignature`, rồi rebuild API. Không đặt PFX/private signing key trên dashboard.
- Administrative extraction `msiexec /a` trên laptop phát triển bị Windows Installer/sandbox treo; đúng process thử nghiệm đã được dừng và không cài service lên laptop. Phải cài/reboot/uninstall MSI trên Windows Server staging.

## Linux artifact

- File: `agent/linux/x86_64/tram-agent`; kích thước `16,634,544` bytes.
- Phiên bản: `0.8.8`; SHA-256 `D7F295F231D3FFCF1E821EC2B4D4F4D06BA2B7CB9D0D21C7DA65355FE5E36A7E`.
- GitHub Actions run `32325161416` build bằng `python-build-standalone` CPython 3.11.15 release `20260623`, xác minh runtime SHA-256 rồi chạy `--help` và `diagnose`/inventory thật trên Ubuntu 22.04/24.04, Oracle Linux 7/8 và Red Hat UBI 7/8. Artifact sinh từ source commit `73d08f7e31cc2726990b1a7ad1b18c89a34c4a06`.
- `.run` do website sinh chỉ chứa binary này, service, VERSION, bootstrap dùng một lần và CA pin; không còn chứa source/requirements hoặc gọi repository Internet.

## Reverse tunnel và truyền file vẫn giữ nguyên

- Agent outbound WebSocket mTLS `9443`; API/Guacamole không kết nối trực tiếp IP máy đích.
- Agent chỉ relay `127.0.0.1:22` cho SSH hoặc `127.0.0.1:3389` cho RDP, tối đa 4 tunnel; không fallback trực tiếp.
- API gửi lệnh mở tunnel và chờ Agent gắn stream mTLS thành công trước khi trả relay port cho Guacamole. Điều này loại bỏ race khiến `guacd` kết nối trước Agent và biến lỗi sshd/RDP local thành HTTP 409 có hướng dẫn; Agent 0.4.2 phải được cập nhật trên endpoint để gửi đúng SSH host key.
- Pin SSH host key/RDP certificate, tắt clipboard/SFTP/RDP drive/printing, giữ recording.
- File một chiều: giới hạn 1 GiB, ClamAV trung tâm, AES-GCM theo khối trong PostgreSQL, job trực tiếp, SHA-256 và Defender/ClamAV endpoint; không auto-run/overwrite/server-to-server. Agent cũ trước 0.8.8 vẫn từ chối file trên 50 MiB, vì vậy endpoint phải được nâng trước khi test file lớn.
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

Riêng bản 0.8.0 phải recreate `api`, `dashboard` và `caddy` để nhận artifact, RBAC UI và security headers mới:

```bash
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard caddy
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api guacamole guacd
```

Từ 0.8.0 lên 0.8.1 chỉ cần rebuild/recreate API để nhận code bootstrap và hai artifact Agent mới; không có thay đổi dashboard/Caddy trong bản này:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
```

Từ 0.8.1 lên 0.8.2 phải rebuild/recreate cả API và dashboard để nhận schema PostgreSQL mới, kiểm soát visibility/share/retire ở API, giao diện process/user mới và hai artifact Agent 0.8.2:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Từ 0.8.2 lên 0.8.3 phải rebuild/recreate API và dashboard để API phát đúng bộ cài 0.8.3 và UI phân biệt scan Windows Update hoàn tất/chưa hoàn tất:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Từ 0.8.3 lên 0.8.4 phải rebuild/recreate API và dashboard để API phát artifact 0.8.4, dashboard nhận semantics resize/MFA/process mới; sau đó nâng Agent endpoint lên 0.8.4 và quét lại Disk/Processes/Updates:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Từ 0.8.4 lên 0.8.5 phải rebuild/recreate API và dashboard để API phát artifact 0.8.5, dashboard nhận đúng adjacent extent/DiskPart, multitask Agent và refresh fleet cục bộ; sau đó nâng Agent endpoint lên 0.8.5 và quét lại Disk/Processes/Updates:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Từ 0.8.5 lên 0.8.6 phải rebuild/recreate API và dashboard để API phát artifact 0.8.6 và giao diện căn sector trước khi gửi dung lượng; sau đó nâng Agent Linux lên 0.8.6 rồi quét lại Disk trước khi thử Extend:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Từ 0.8.6 lên 0.8.7 phải rebuild/recreate API và dashboard để API phát đúng artifact 0.8.7, dashboard nhận giao diện Updates gọn và wizard task cập nhật hàng loạt; sau đó nâng Agent endpoint lên 0.8.7 để nhận probe Windows Update/WSUS và repository Linux hữu hạn:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Thay đổi đồng bộ LDAP/AD sau 0.8.7 chỉ nằm ở control plane/dashboard, không đổi Agent. Sau pull chỉ cần rebuild/recreate `api` và `dashboard`; mở **Người dùng & vai trò** rồi bấm **Đồng bộ AD** một lần nếu cấu hình LDAP đã được lưu từ bản cũ:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Từ 0.8.7 lên 0.8.8 phải render lại Nginx để nhận `client_max_body_size 1100m`, rebuild/recreate API/dashboard/Caddy/ClamAV để tạo bảng chunk và nhận giới hạn scan mới, rồi nâng Agent endpoint lên 0.8.8 trước khi thử file lớn:

```bash
git pull --ff-only origin main
sudo sh deploy/configure-nginx.sh ops.sbsi.vn /path/to/public-fullchain.pem /path/to/public-private-key.pem
nginx -t && systemctl reload nginx
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard caddy clamav
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard caddy clamav
```

Từ 0.8.8 lên 0.8.9 phải pull commit đã bundle artifact, rebuild/recreate API và dashboard, rồi nâng Agent trên endpoint trước khi dùng nút **Nguồn cập nhật**. Không áp dụng cấu hình repo/WSUS từ dashboard cho Agent cũ vì action mới chưa có trong allowlist của Agent đó:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard
docker compose -f compose.yaml -f compose.test.yaml exec api cat /opt/tram-agent-assets/VERSION
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard
```

Sau khi endpoint lên 0.8.9, vào tab **Cập nhật → Nguồn cập nhật**, đọc nguồn hiện tại rồi thử trên staging: Ubuntu phải giữ Docker/PPA; Oracle phải giữ EPEL/Docker/repo ứng dụng; Windows WSUS phải hiện đúng URL và `UseWUServer=1`. Lưu cấu hình xong phải xuất hiện job đọc nguồn và quét patch mới.

Bản xử lý ANTT 20/08 chỉ đổi control plane/dashboard/proxy, không tăng Agent khỏi `0.8.8`. Sau pull phải render lại Nginx, rebuild/recreate `api`, `dashboard`, `caddy`, rồi đăng nhập lại vì token cũ chưa có `jti` bị từ chối chủ động:

```bash
git pull --ff-only origin main
sudo sh deploy/configure-nginx.sh ops.sbsi.vn /path/to/public-fullchain.pem /path/to/public-private-key.pem
nginx -t && systemctl reload nginx
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api dashboard caddy
docker compose -f compose.yaml -f compose.test.yaml logs --tail=200 api dashboard caddy
```

API tự tạo bảng `revoked_session_tokens` khi khởi động. Kiểm tra browser không còn key `tram_ops_token` trong Session Storage; logout xong gọi lại `/api/v1/me` với cookie hoặc Bearer cũ phải nhận `401`. Cấu hình LDAP cũ có `use_ssl=false` sẽ bị từ chối khi sử dụng và phải lưu lại bằng LDAPS hợp lệ.

API tự tạo các bảng PostgreSQL mới khi khởi động; không có migration làm thay đổi hoặc xóa dữ liệu bảng hiện hữu.

Máy đã tạo `guacd`/`guacamole` trước bản sửa Docker DNS phải recreate đúng hai container để endpoint nhận alias mới:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --force-recreate guacd guacamole
docker compose -f compose.yaml -f compose.test.yaml exec guacamole getent hosts guacd
```

Lệnh cuối phải trả về IP nội bộ và tên `guacd`. Nếu rỗng, kiểm tra `docker inspect` của hai container; cả hai phải cùng network `*_session`, trong đó `guacd` có alias/DNS name `guacd`.

Sau bản sửa host-key/recording, phải rebuild API, recreate các container dùng quyền volume và cập nhật agent:

```bash
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate recording-init api guacd guacamole
docker compose -f compose.yaml -f compose.test.yaml exec guacd id
docker compose -f compose.yaml -f compose.test.yaml logs --tail=100 recording-init api guacd guacamole
```

`guacd` phải chạy UID/GID `1000`; log phiên SSH mới không còn `Host key does not match` hoặc `Creation of recording/typescript failed: Permission denied`. Không dùng nút reconnect của phiên cũ vì relay mỗi phiên là một lần.

Endpoint Linux đã enroll nâng cấp thủ công lên 0.8.7 như sau, không enroll lại và không thay certificate/config hiện có. Không chạy lại `.run` một lần của máy mới; copy executable đã bundle cùng unit systemd rồi restart:

```bash
cd /home/system/dashboard-mgmt
sudo install -m 0755 agent/linux/x86_64/tram-agent /opt/tram-agent/tram-agent
sudo install -m 0644 agent/VERSION /opt/tram-agent/VERSION
sudo install -m 0644 agent/tram-agent.service /etc/systemd/system/tram-agent.service
sudo systemctl daemon-reload
sudo systemctl restart tram-agent
sudo systemctl status tram-agent --no-pager
```

Gói `.run` sinh sau bản sửa installer cũng có thể dùng để nâng cấp trực tiếp máy đã enroll: installer tự giữ identity và restart service. Nếu từng chạy gói cũ rồi gặp `HTTP 409`, binary đã được chép nhưng service có thể đang dừng; chạy `sudo systemctl enable --now tram-agent.service` để phục hồi ngay. Nếu installer báo identity không đầy đủ, không xóa `/etc/tram-agent` tùy tiện: kiểm tra backup certificate/key hoặc retire đúng server cũ trên dashboard trước khi clean-enroll.

Chờ một lần check-in mới để PostgreSQL nhận ECDSA host key rồi bấm **Mở SSH** tạo phiên hoàn toàn mới. Không dùng **Reconnect** của phiên cũ.

Nếu SSH mở ra trang **RECENT CONNECTIONS / ALL CONNECTIONS** thay vì terminal, pull bản sửa route client và chỉ rebuild API:

```bash
cd /home/system/dashboard-mgmt
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate api
```

Sau đó quay lại dashboard và tạo phiên SSH mới. URL đúng phải chứa `/guacamole/#/client/`; log `guacd` phải xuất hiện cho phiên đó.

Nếu route client báo **The requested connection does not exist**, phải rebuild cả dashboard để nhận bản tự xóa token Guacamole cũ:

```bash
cd /home/system/dashboard-mgmt
git pull --ff-only origin main
docker compose -f compose.yaml -f compose.test.yaml up -d --build --force-recreate dashboard
```

Hard refresh dashboard rồi tạo phiên mới; không mở/đăng nhập Guacamole thủ công trước khi bấm **Mở SSH**.

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

- Sau khi artifact được bundle, trang **Bộ cài Agent** phải hiển thị đúng URL production, Agent `0.8.8`, Linux available và Windows MSI 0.8.8 available.
- `agentTlsCaAvailable=true`; không còn cảnh báo CA và label/ô nhập không dính nhau.
- Tải Linux trả `.run`; tải Windows trả MSI có tên dài bắt đầu `TramAgent--`.
- Không có domain `example` trong config sinh ra nếu `dashboard_url` đã đặt đúng.
- Không public port nội bộ.

Production PostgreSQL bên ngoài dùng `compose.external.yaml` thay `compose.test.yaml`.

## Chẩn đoán Windows Update ngày 19/08/2026

- Máy được gọi là **có WSUS** đang có `WUServer=http://wsus.sbsi.vn:8530`, `DoNotConnectToWindowsUpdateInternetLocations=1` và target group, nhưng khóa `AU\UseWUServer=1` không tồn tại. WUA báo default service là Windows Update public và `IsManaged=false`; như vậy public source bị policy chặn trong khi WSUS chưa được kích hoạt. Phải sửa GPO WSUS trung tâm để sinh `UseWUServer=1`, bảo đảm endpoint tới `wsus.sbsi.vn:8530`, chạy `gpupdate /force` rồi quét lại. Không sửa registry local thủ công nếu khóa do domain GPO quản lý.
- Máy **không WSUS** không có khóa WUServer, dùng direct WinHTTP và WUA báo lần search thành công gần nhất `28/07/2026`; các patch trong Windows Settings là dữ liệu orchestration/cache từ lần đó. WUA online hiện treo quá timeout, nên chưa có căn cứ kết luận 0 update. Cần kiểm tra outbound/proxy/DNS/TLS của tài khoản LocalSystem tới Windows Update và WindowsUpdateClient event sau lần quét mới. BITS `Stopped/Manual` tự nó không phải lỗi vì đây là trigger-start service.
- Agent/dashboard 0.8.5 đưa đúng hai trạng thái này lên banner gọn và giải thích vì sao Settings còn hiện cache/Pending install. Chỉ khi `currentScanComplete=true` mới cho chọn/cài patch; lần quét chưa hoàn tất không ghi đè ý nghĩa của kết quả hoàn tất gần nhất.

## Smoke test bắt buộc

1. Mở dashboard bằng domain thật, vào **Bộ cài Agent**, lưu đúng URL HTTPS.
2. Sau khi artifact 0.8.9 được bundle, tải từng Linux `.run` mới, cài khi chặn Internet trên Ubuntu 22.04/24.04, Oracle Linux 7/8 và RHEL 7/8 staging; xác nhận không còn warning tar epoch, claim trả 201, service running, agent `0.8.9`, unit có `AF_NETLINK`, tự vào Linux và `tunnelOnline=true`. Package cũ đã hết hạn/đã dùng thì phải tạo package mới.
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
11. Trên Windows, Ubuntu, Red Hat và Oracle Linux staging, quét từng tab mới; xác nhận danh sách là dữ liệu thật của endpoint, action mutation tự sinh job quét lại và UI cập nhật sau check-in kế tiếp.
12. Với Disk, chỉ test extend/shrink/create/delete trên disk dữ liệu staging đã snapshot/backup. Riêng Windows layout đang chụp phải bật Extend cho C: với đúng 10 GiB liền kề (không cộng 10 GiB sau Recovery), Shrink phải mở modal và DiskPart phải tạo segment mới ngay bên phải C:. Xác nhận EFI/MSR/Recovery/OEM bị khóa, capacity vượt giới hạn bị chặn và filesystem/mount/fstab sau reboot đúng như UI. Không dùng Shrink để cố di chuyển Recovery.
13. Chọn đúng một update trong danh sách và xác nhận chỉ gói/version đó được cài; không có luồng update-all. Trên Windows, xác nhận trạng thái WUA là `ok`; `cached` chỉ là dữ liệu cục bộ cũ. Nếu còn `0x80072EE2`, sửa outbound firewall/proxy/WSUS của LocalSystem rồi quét lại, không coi 0 dòng là “đã cập nhật hết”.
14. Trong danh sách Windows và Linux, chọn nhiều máy rồi tạo thử user thường/user quản trị và rule SSH Inbound. Xác nhận từng target có job riêng, Windows dùng Administrators/Windows Firewall, Ubuntu dùng sudo/UFW, Oracle Linux và Red Hat dùng wheel/default firewalld zone; sau firewall mutation phải có `firewall.list` tự động.

## Kiểm thử local đã đạt

- Control plane `47/47`, gồm validate nguồn cập nhật theo OS/version, URL an toàn và quyền `updates.manage`; cùng browser cookie session không lộ token qua Web Storage, logout thu hồi `jti` PostgreSQL và chặn replay, CSRF same-origin, audit mọi `403`, lọc audit, bắt buộc LDAPS, bảo vệ catalog role và tách quyền cấu hình log; cùng tự phục vụ hồ sơ/mật khẩu Local, chống tự nâng role, Administrator-only reset MFA và QR đăng ký lại; file upload mã hóa theo chunk và stream giải mã có kiểm tra thứ tự/hash; scan ClamAV từ upload spool; đồng bộ thành viên AD trực tiếp/lồng nhau có paging, giữ role/trạng thái gán riêng và đối chiếu username không phân biệt hoa thường; cùng catalog bulk update chỉ lấy giao patch của cùng OS/version/architecture và ghim đúng revision riêng từng server, Viewer first-login nhận QR MFA, direct/group server share, retire, guest surface/docs 404, route-auth audit, PostgreSQL login throttle, Viewer RBAC workspace, bundle Linux ELF offline, batch task, recording retention, auto-scan, active-job heartbeat/requeue/idempotent result, audit retention, validation, custom role/LDAP role, recording diagnostics/delete, output RBAC, Guacamole route, CA pin, OS binding, replay rejection và tunnel chuẩn bị trước Guacamole.
- Agent security `71/71`, gồm chuyển/khôi phục nguồn Ubuntu và Oracle mà giữ nguyên Docker/PPA/EPEL/repo ứng dụng, validate URL, xác minh policy WSUS/Internet có hiệu lực thật và fail-closed khi mất trạng thái khôi phục Oracle; cùng probe Windows Update/WSUS hữu hạn, dừng ngay khi mất nguồn, APT/YUM repository failure có cấu trúc và applicability theo release; căn dung lượng LVM xuống sector 512, Windows DiskPart Extend/Shrink, OL7 partition geometry/adjacency, CLIXML cleanup, nhận diện WSUS/direct/incomplete policy, pin WUA `ServerSelection`, cache freshness, khóa cài từ scan chưa hoàn tất, upgrade identity, Oracle/RHEL 7 `lsblk --pairs`, process CPU/RAM, bootstrap detail, installer offline, firewall/storage/update/process/log/account validation, `AF_NETLINK`, command-path fallback, Docker lock, SSH host key, MSI locator/bootstrap TLS và version contract.
- `deploy/configure-nginx.sh` integration test chạy lặp hai lần: giữ nguyên secret, không nhân đôi key và tạo backup đúng.
- ESLint pass.
- Vinext production build pass.
- Render trực quan form bộ cài pass: label dùng grid, gap `7px`, input/select cao `40px`; tab kiểm thử và server tạm đã đóng/xóa.
- Render test workspace `21/21` pass, gồm đồng hồ nhảy từng giây, tìm kiếm từ/cụm từ tiếng Việt/English có hoặc không dấu trong Công việc và Nhật ký kiểm toán, loại tên thành phần nội bộ khỏi nội dung giao diện; cùng biểu đồ sức khỏe theo phần trăm fleet thật, theme sáng/tối theo giờ hệ thống, lớp chống chữ sáng bị chìm trên toàn dashboard, thẻ chọn/máy đích/nút nhỏ của light theme và các vùng terminal tối có chủ đích; cookie auth/logout không lưu access token, LDAPS bắt buộc, quyền cấu hình log, bộ lọc audit và CSP mới; sidebar kéo ngang/tự wrap và điều khiển bàn phím, login card theo viewport, tên thao tác dễ đọc, shell/sidebar không bị phóng đại hoặc hụt chân trang, recent audit thật, process realtime không chớp pending, file 1 GiB/form reset an toàn, QR MFA tương thích CSP, process CPU/RAM realtime/sort/filter, server share và platform group; các kiểm tra permission-aware cho Viewer, shell/fleet/modal/task/firewall/recording/storage/update/user-role trước đó vẫn pass. Browser fixture light theme đo tương phản thấp nhất `4.62:1` cho text bình thường và đã được gỡ sau khi kiểm tra.
- Kiểm tra browser local bằng dữ liệu mẫu pass: cây Disk mở đúng cấp; modal hiển thị footer ở desktop và cuộn nội bộ tại `390x700`; Services/Users giữ bố cục; log tô toàn dòng error đỏ và warning vàng. Route dữ liệu mẫu và dev server đã gỡ/dừng trước commit.
- Render trực quan modal thêm firewall pass trên Windows profile, Ubuntu/UFW, Oracle Linux/firewalld zone và Red Hat/iptables INPUT/OUTPUT. DOM đo ở 1024x600 và 390x700 xác nhận modal nằm trọn viewport, không có tràn ngang, body có thanh cuộn riêng và footer luôn hiển thị.
- Python `py_compile` pass.
- XML/YAML/PowerShell syntax pass.
- Máy phát triển không có Docker; `compose.yaml` đã parse/kiểm tra cấu trúc bằng PyYAML, còn `docker compose config` và recreate thực tế phải xác nhận trên Ubuntu deployment.
- GitHub Actions cho 0.8.8: security audit run `32325161387` pass; Linux build run `32325161416` pass `--help` và `diagnose` trên đủ sáu image OS; MSI run `32325161405` pass và ProductVersion đọc trực tiếp là `0.8.8`. Bước ký EXE/MSI được skip đúng thiết kế vì repository chưa cấu hình code-signing secrets.

## Sites

- `.openai/hosting.json` đã gắn với private Sites project `appgprj_6a852d7a7310819194555fde1d13573f` để không tạo trùng project ở lần sau.
- Project chưa được publish. Production vẫn là Docker/Nginx tại domain vận hành; việc đẩy toàn bộ source sang repository riêng của Sites cần quản trị viên xác nhận riêng trước khi thực hiện.

## Ưu tiên sau smoke test

### Cập nhật Extend và audit retention 2026-08-17

- Dashboard luôn hiển thị nút `Extend` trên partition/LV. Nút bật khi Agent báo tối thiểu 1 MiB có thể mở rộng; root LV Linux được extend nhưng vẫn khóa xóa, còn partition boot/root trực tiếp tiếp tục được bảo vệ.
- Windows yêu cầu unallocated space liền kề ngay bên phải. Với layout hiện tại `C: -> 10 GiB Unallocated -> Recovery -> 10 GiB Unallocated`, `Extend` của C: phải bật với đúng 10 GiB đầu tiên; 10 GiB sau Recovery không được cộng vào capacity. Ứng dụng không tự di chuyển/xóa Recovery.
- Audit API trả thêm `detail`, phân trang 500 dòng và giao diện hiển thị cụ thể server/action/risk để truy ra ai đã thao tác gì.
- PostgreSQL tự xóa audit event quá 30 ngày khi API startup và mỗi giờ. Mỗi lần dọn có audit event riêng và lưu hash neo tại `system_settings.audit_retention_anchor`.
- Ghi chú lịch sử của bản 17/08: thay đổi lúc đó không đổi Agent/MSI và production dùng Agent `0.7.2`; trạng thái hiện tại đã được thay bằng Agent/MSI `0.8.8` ở phần trên.
- Sửa nhận diện LV khi `lsblk` trả `/dev/mapper/<vg>-<lv>` nhưng `lvs` trả `/dev/<vg>/<lv>`: dashboard ánh xạ đúng quy tắc escape dấu gạch ngang của device-mapper, nên root LV hiện lại nút Extend và dùng đúng path do `lvs` cung cấp cho Agent.
- Unallocated Windows không phải partition nên không hỗ trợ kéo-thả. Nếu Recovery nằm giữa C: và vùng trống, Windows native chỉ extend sau khi Recovery được di chuyển hoặc xóa/tạo lại trong maintenance window có backup; dashboard chỉ báo khóa, không tự làm thao tác phá hủy này.

1. Cấu hình enterprise/EV code-signing certificate cho workflow và thay artifact unsigned.
2. Lập luồng migrate domain/CA có dual-endpoint overlap cho agent cũ; không tắt domain cũ đột ngột.
3. Tích hợp Vault/LAPS cho credential SSH/RDP.
4. Immutable/WORM storage cho recording/audit.
5. Distributed tunnel broker trước khi scale API.
6. CRL/OCSP và certificate rotation tự động.
7. EDR/WDAC/AppLocker/SELinux, micro-segmentation và pentest độc lập.

## Nguyên tắc không phá vỡ

- Không thêm shell/PowerShell tùy ý hoặc destination tunnel tùy ý.
- Không bỏ mTLS, request signature, TLS pin/hostname verification, RBAC, MFA hoặc audit.
- Không log/commit `.env`, password, raw claim, token, private key, DB URL có password, PFX hoặc recording.
- Không cho file tự chạy và không bật lại clipboard/SFTP/RDP drive.
- Không public ClamAV, guacd, PostgreSQL hoặc relay.
- Không sửa bytes MSI riêng theo từng server vì sẽ phá chữ ký; locator dùng một lần phải nằm trong tên file.
