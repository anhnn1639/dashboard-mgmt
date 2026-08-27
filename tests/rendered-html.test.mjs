import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } }, { waitUntil() {}, passThroughOnException() {} });
}

test("server-renders the secure operations console shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>Trạm Vận Hành<\/title>/i);
  assert.match(html, /Đang kiểm tra cấu hình hệ thống/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("dashboard includes automatic Windows and Linux fleet views", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  assert.match(source, /Máy chủ Linux/);
  assert.match(source, /Máy chủ Windows/);
  assert.match(source, /server\.osFamily === scope/);
  assert.match(source, /\/api\/v1\/servers/);
  assert.match(source, /Phiên truy cập/);
  assert.match(source, /Nhật ký kiểm toán/);
  assert.match(source, /serverRoute\(server\)/);
  assert.match(source, /Truyền file/);
  assert.match(resources, /service\.restart/);
  assert.match(source, /firewall\.list/);
  assert.match(resources, /Disk & Volumes/);
  assert.match(resources, /Users & Groups/);
  assert.match(resources, /patch\.install/);
  assert.match(resources, /objectArray\(value\.partitions\)\.map\(normalizeStorageNode\)/);
  assert.match(resources, /objectArray\(payload\.updates\)/);
  assert.match(resources, /process\.kill/);
  assert.match(resources, /Tối đa 500 dòng/);
  assert.match(source, /\/api\/v1\/setup\/status/);
  assert.match(source, /Kết nối kho dữ liệu/);
  assert.match(source, /Admin local đầu tiên/);
});

test("resource dialogs fit the viewport and scroll internally", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(styles, /\.resource-modal\s*{[^}]*max-height:\s*calc\(100vh - 16px\)/s);
  assert.match(styles, /\.resource-modal\s*{[^}]*max-height:\s*calc\(100dvh - 16px\)/s);
  assert.match(styles, /\.resource-modal\s*{[^}]*max-height:\s*100%/s);
  assert.match(styles, /\.resource-modal-body\s*{[^}]*overflow:\s*auto/s);
  assert.match(styles, /\.resource-modal-footer\s*{[^}]*flex:\s*0 0 auto/s);
  assert.match(source, /id="ldap-settings-form"/);
  assert.match(source, /form="ldap-settings-form"/);
  assert.match(source, /className="ldap-settings-modal"/);
  assert.match(styles, /\.storage-tree\s*{[^}]*overflow:\s*auto/s);
  assert.match(styles, /\.resource-table-scroll\s*{[^}]*overflow:\s*auto/s);
  assert.match(styles, /\.login-card\s*{[^}]*max-height:\s*calc\(100dvh - 24px\)/s);
  assert.match(styles, /\.login-card\s*{[^}]*overflow-y:\s*auto/s);
});

test("Windows and Linux fleets can queue OS-aware common tasks", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /Tạo task chung/);
  assert.match(source, /\/api\/v1\/bulk-tasks/);
  assert.match(source, /firewall\.rule\.add\.auto/);
  assert.match(source, /Windows dùng group Administrators theo SID/);
  assert.match(source, /Oracle Linux\/Red Hat chọn default firewalld zone/);
  assert.match(source, /server_ids:\s*targetIds/);
  assert.match(source, /initialServerIds=\{selectedServerIds\}/);
});

test("firewall add form uses server capabilities and a viewport-safe scroll region", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /Dữ liệu trực tiếp từ máy chủ/);
  assert.match(source, /Profile Windows Firewall/);
  assert.match(source, /Zone firewalld/);
  assert.match(source, /Filter chain trên máy chủ/);
  assert.match(source, /capabilities\.targets\.map/);
  assert.match(source, /hệ thống đang tự quét lại danh sách/);
  assert.match(source, /Thực thi trực tiếp có kiểm soát/);
  assert.match(source, /Đang chờ Agent nhận tác vụ/);
  assert.match(source, /chi tiết từ Agent ở bên dưới/);
  assert.match(source, /job-error-output/);
  assert.match(source, /Exit code/);
  assert.match(source, /autoRefreshForLatestMutation\.status !== "succeeded"/);
  assert.doesNotMatch(source, /\/api\/v1\/jobs\/\$\{jobId\}\/approve/);
  assert.doesNotMatch(source, /Phê duyệt/);
  assert.doesNotMatch(source, /Table<input name="table"/);
  assert.doesNotMatch(source, /Chain<input name="chain"/);
  assert.match(styles, /\.add-firewall-modal\s*{[^}]*max-height:\s*calc\(100% - 32px\)/s);
  assert.match(styles, /\.firewall-add-scroll\s*{[^}]*overflow-y:\s*auto/s);
});

test("firewall rules are searchable and filterable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /aria-label="Tìm firewall rule"/);
  assert.match(source, /firewallActionFilter/);
  assert.match(source, /firewallDirectionFilter/);
  assert.match(source, /firewallStateFilter/);
  assert.match(source, /firewallBackendFilter/);
  assert.match(source, /filteredFirewallRules\.map/);
});

test("recording deletion requires a distinct second administrator", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /recording-deletion-requests/);
  assert.match(source, /Người tạo yêu cầu không được tự duyệt/);
  assert.match(source, /Chờ quản trị viên khác/);
  assert.match(source, /Gửi yêu cầu xóa/);
  assert.match(source, /selectedRecordingIds/);
  assert.match(source, /Lý do \/ ticket là bắt buộc/);
  assert.match(source, /settings\/recording-retention/);
  assert.match(source, /Mặc định 180 ngày/);
});

test("storage resize stays explicit and Updates shows only patches", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  const updateSettings = await readFile(new URL("../app/update-source-settings.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(resources, /<span>Thao tác<\/span>/);
  assert.match(resources, /disabled=\{!canExtend\}/);
  assert.match(resources, /partition Recovery hoặc partition khác đang nằm ở giữa/);
  assert.match(resources, /logicalVolumeMapperPath\(item\) === node\.path/);
  assert.match(resources, /Unallocated không thể kéo thả/);
  assert.match(resources, /queue\("storage\.shrink"/);
  assert.match(resources, /Thứ tự vật lý các phân vùng/);
  assert.match(resources, /type === "unallocated"/);
  assert.match(resources, /Shrink không di chuyển phần đang chắn/);
  assert.match(resources, /Agent dùng DiskPart giống Disk Management/);
  assert.equal((resources.match(/\/ 512\) \* 512/g) || []).length, 2);
  assert.match(resources, /Logical Volumes/);
  assert.match(resources, /Extend LV/);
  assert.match(resources, /resizeProtected: Boolean\(node\.resizeProtected\)/);
  assert.doesNotMatch(resources, /Windows Update API/);
  assert.doesNotMatch(resources, /Configuration Manager/);
  assert.match(resources, /objectArray\(payload\.updates\)/);
  assert.match(resources, /diagnostics\.currentScanComplete === true/);
  assert.doesNotMatch(resources, /Chưa thể kết luận máy có 0 bản cập nhật/);
  assert.doesNotMatch(resources, /Đang hiển thị dữ liệu hoàn tất gần nhất/);
  assert.match(resources, /Không có Internet/);
  assert.match(resources, /Mất kết nối WSUS/);
  assert.match(resources, /Không kết nối được repository/);
  assert.match(resources, /Phiên bản hệ điều hành/);
  assert.doesNotMatch(resources, /Nguồn cập nhật của máy chủ/);
  assert.doesNotMatch(resources, /patch\.source\.configure/);
  assert.match(source, /label: "Cấu hình cập nhật"/);
  assert.match(updateSettings, /Cấu hình nguồn cập nhật hàng loạt/);
  assert.match(updateSettings, /Microsoft Update qua Internet/);
  assert.match(updateSettings, /Ép dùng WSUS/);
  assert.match(updateSettings, /Repo Oracle Linux nội bộ/);
  assert.match(updateSettings, /Docker, PPA và repo ứng dụng khác được giữ nguyên/);
  assert.match(updateSettings, /URL Pulp Distribution cho từng nguồn Ubuntu/);
  assert.match(updateSettings, /Base, Updates và Security là bắt buộc; Backports để trống nếu chưa đồng bộ/);
  assert.match(updateSettings, /Chữ màu xám trong ô chỉ là ví dụ, không phải dữ liệu đã lưu/);
  assert.match(updateSettings, /onSubmit=\{applySources\} noValidate/);
  assert.match(updateSettings, /setMessage\(formValidationMessage\)/);
  assert.match(updateSettings, /disabled=\{Boolean\(busy\)\}/);
  assert.match(updateSettings, /repositories: ubuntuRepositorySuites/);
  assert.match(updateSettings, /\/api\/v1\/bulk-update-sources\/catalog/);
  assert.match(updateSettings, /"patch\.source\.configure"/);
  assert.match(updateSettings, /Áp dụng cho \$\{selectedIds\.length\} máy/);
  assert.match(styles, /input:not\(\[type="checkbox"\]\):not\(\[type="radio"\]\)/);
  assert.match(styles, /\.update-settings-layout\s*{[^}]*grid-template-columns:/s);
  assert.match(source, /"patch\.source\.read": "Đọc nguồn cập nhật"/);
  assert.match(source, /"patch\.source\.configure": "Cấu hình nguồn cập nhật"/);
  assert.match(source, /successfulUpdateScanJobs/);
  assert.match(source, /Cập nhật bản vá theo OS \+ version/);
  assert.match(source, /\/api\/v1\/bulk-update\/catalog/);
  assert.match(source, /Tiếp: Chọn patch/);
  assert.match(source, /Patch chung cho toàn bộ máy đã chọn/);
  assert.match(source, /Chi tiết thao tác/);
  assert.match(source, /Tải thêm nhật ký/);
  assert.match(source, /tự động dọn dữ liệu cũ sau \{auditRetentionDays\} ngày/);
  assert.match(source, /loadServers\(true\)/);
});

test("platform users, LDAP assignments and custom roles are editable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /Tạo tài khoản Local/);
  assert.match(source, /Cấu hình LDAP \/ Active Directory/);
  assert.match(source, /Đồng bộ AD/);
  assert.match(source, /settings\/ldap\/users\/sync/);
  assert.match(source, /user\.source === "ldap" \? "AD" : "Local"/);
  assert.match(source, /gán mọi role hiện có/);
  assert.doesNotMatch(source, /xuất hiện sau lần đăng nhập Domain đầu tiên/);
  assert.match(source, /Roles & quyền hạn/);
  assert.match(source, /permission-groups/);
  assert.match(source, /Groups của trạm vận hành/);
  assert.match(source, /allowed_group_dns/);
  assert.match(source, /Quét groups/);
  assert.match(source, /platform-groups/);
  assert.match(source, /method: "PATCH"/);
  assert.match(source, /method: "DELETE"/);
  assert.match(source, /Thông tin tài khoản/);
  assert.match(source, /\/api\/v1\/me\/profile/);
  assert.match(source, /\/api\/v1\/me\/password/);
  assert.match(source, /name="current_password"/);
  assert.match(source, /Role và tên đăng nhập không bị thay đổi/);
  assert.match(source, /Tên hiển thị và mật khẩu của tài khoản AD được quản lý tại Active Directory/);
  assert.match(source, /\/api\/v1\/users\/\$\{user\.id\}\/mfa/);
  assert.match(source, /currentUser\.role === "admin"/);
  assert.match(source, />Reset MFA<\/button>/);
  assert.match(source, /Lần đăng nhập sau sẽ hiển thị QR mới/);
  assert.match(source, /LDAPS bắt buộc/);
  assert.match(source, /use_ssl: true/);
  assert.doesNotMatch(source, /name="use_ssl"/);
  assert.match(styles, /\.account-settings-modal\s*{[^}]*width:\s*min\(720px, calc\(100vw - 16px\)\)/s);
  assert.match(styles, /\.account-identity-summary\s*{[^}]*grid-template-columns:\s*repeat\(2, minmax\(0, 1fr\)\)/s);
});

test("dashboard authentication uses a revocable HttpOnly cookie instead of web storage", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /COOKIE_SESSION_MARKER = "cookie-session"/);
  assert.match(source, /\/api\/v1\/auth\/logout/);
  assert.match(source, /"X-Tram-Auth-Mode": "cookie"/);
  assert.doesNotMatch(source, /sessionStorage/);
  assert.doesNotMatch(source, /tram_ops_token/);
});

test("process resources and server visibility controls are operable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(resources, /cpuPercent/);
  assert.match(resources, /memoryBytes/);
  assert.match(resources, /Realtime 5s/);
  assert.match(resources, /refreshRef\.current/);
  assert.match(resources, /jobRef\.current/);
  assert.match(resources, /job\?\.status === "failed" && <PendingState job=\{job\}/);
  assert.match(resources, /Đã khóa \/ disable/);
  assert.match(resources, /Unlock tài khoản/);
  assert.match(source, /Share \$\{server\.name\}/);
  assert.match(source, /Xóa máy chủ/);
  assert.match(source, />Delete<\/button>/);
  assert.match(source, /<JobsView token=\{token\} servers=\{servers\}/);
  assert.match(source, /new Map\(servers\.map\(\(server\) => \[server\.id, server\]\)\)/);
  assert.match(source, /currentServer\?\.name \|\| job\.serverName \|\| job\.serverId\.slice/);
  assert.match(source, /currentServer\?\.address \|\| job\.serverAddress \|\| "chưa có IP"/);
  assert.match(source, /serverIdentity\(job\)/);
  assert.match(source, /className="job-server-hostname"/);
  assert.match(source, /className="job-server-address"/);
  assert.match(styles, /\.job-server-label\s*{[^}]*gap:\s*7px/s);
  assert.match(styles, /\.job-server-hostname\s*{[^}]*color:\s*#f4f7ff;[^}]*font-weight:\s*700/s);
  assert.match(styles, /\.job-server-address\s*{[^}]*color:\s*#66b7ff;[^}]*font-weight:\s*400/s);
  assert.match(styles, /\.server-delete-button\s*{[^}]*min-height:\s*30px/s);
  assert.match(source, /servers\.manage/);
  assert.match(source, /\/api\/v1\/audit\?limit=6/);
  assert.match(source, /overview-activity-list/);
  assert.match(source, /File tối đa 1 GiB/);
  assert.match(source, /const formElement = event\.currentTarget/);
  assert.match(source, /currentUser\.permissions\.includes\("logs\.configure"\)/);
  assert.match(source, /audit-filter-bar/);
  assert.match(source, /visibleAuditRows/);
});

test("job and audit action codes have readable labels", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /"file\.deliver": "Truyền file an toàn tới máy chủ"/);
  assert.match(source, /"process\.list": "Đọc danh sách tiến trình"/);
  assert.match(source, /jobActionLabel\(job\.action\)/);
  assert.match(source, /auditActionLabel\(event\.action, event\.detail\)/);
  assert.match(source, /auditActionLabel\(row\.action, row\.detail\)/);
  assert.match(source, /action === "job\.succeeded"/);
});

test("overview health chart uses live fleet percentages and the operator system theme", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /function healthPercentages/);
  assert.match(source, /healthyCount = servers\.filter/);
  assert.match(source, /warningCount = servers\.filter/);
  assert.match(source, /criticalCount = servers\.filter/);
  assert.match(source, /--healthy-end/);
  assert.match(source, /--warning-end/);
  assert.match(source, /Trạng thái hiện tại của toàn bộ máy chủ/);
  assert.match(source, /Cập nhật \{systemClock\}/);
  assert.match(source, /setInterval\(updateSystemAppearance, 1_000\)/);
  assert.doesNotMatch(source, />24 giờ/);
  assert.doesNotMatch(source, />7 ngày</);
  assert.doesNotMatch(source, /aria-label="Thông báo"/);
  assert.doesNotMatch(source, /className="help"/);
  assert.match(source, /themeForSystemTime/);
  assert.match(source, /document\.documentElement\.dataset\.theme = nextTheme/);
  assert.match(styles, /html\[data-theme="light"\]/);
  assert.match(styles, /\.donut\s*{[^}]*--healthy-end:[^}]*--warning-end:/s);
  assert.match(styles, /\.donut\.empty\s*{[^}]*background:\s*var\(--line\)/s);
});

test("clock and phrase search work with Vietnamese or English text", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /role="timer"/);
  assert.match(source, /function normalizeSearchText/);
  assert.match(source, /\.normalize\("NFD"\)/);
  assert.match(source, /replace\(\/\\p\{M\}\/gu, ""\)/);
  assert.match(source, /const \[jobSearch, setJobSearch\] = useState\(""\)/);
  assert.match(source, /jobActionLabel\(job\.action\)/);
  assert.match(source, /const visibleAuditRows = useMemo/);
  assert.match(source, /auditActionLabel\(row\.action, row\.detail\)/);
  assert.match(source, /hiddenAuditDetailKeys/);
  assert.match(source, /!hiddenAuditDetailKeys\.has/);
  assert.match(source, /Từ\/cụm từ tiếng Việt hoặc English/);
  assert.match(styles, /\.jobs-toolbar\s*{/);
  assert.doesNotMatch(source, /PostgreSQL|Nginx|Caddy|ClamAV|SECURE CONTROL PLANE|CONTROL PLANE ·/);
  assert.doesNotMatch(resources, /PostgreSQL/);
});

test("light theme keeps legacy and semantic text readable across the dashboard", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?h1,[\s\S]*?textarea[\s\S]*?\)\s*{\s*color:\s*var\(--ink\)\s*!important;/s,
  );
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.job-server-address,[\s\S]*?\)\s*{\s*color:\s*var\(--blue\)\s*!important;/s,
  );
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.job-server-hostname,[\s\S]*?\)\s*{\s*color:\s*var\(--ink\)\s*!important;/s,
  );
  assert.match(
    styles,
    /\.operation-result \*,[\s\S]*?\.recording-screen\s*\)[\s\S]*?background:\s*#0f172a\s*!important;[\s\S]*?color:\s*#e6edf7\s*!important;/s,
  );
  assert.doesNotMatch(styles, /\.recording-screen\s+\*/);
  assert.match(styles, /html\[data-theme="light"\] \.recording-screen > p\s*{[^}]*background:\s*transparent\s*!important;[^}]*color:\s*#e47a82\s*!important;/s);
  assert.match(styles, /html\[data-theme="light"\][\s\S]*?\.jobs-row\.head/);
});

test("light theme recolors selectable cards, state badges, and compact controls", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");

  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.bulk-target-list > label,[\s\S]*?\.choice-grid label,[\s\S]*?\)\s*{\s*background:\s*var\(--panel-2\)\s*!important;/s,
  );
  assert.match(styles, /html\[data-theme="light"\] \.bulk-target-list em\s*{[^}]*color:\s*#176a4e\s*!important;[^}]*background:\s*#e5f5ee\s*!important;/s);
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.storage-row-actions button,[\s\S]*?\)\s*{\s*background:\s*var\(--panel-2\)\s*!important;/s,
  );
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\(\s*\.search kbd,[\s\S]*?\)\s*{\s*background:\s*#e3edf8\s*!important;[\s\S]*?color:\s*var\(--blue\)\s*!important;/s,
  );
});

test("dashboard shell fits the viewport without global zoom", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.doesNotMatch(styles, /body\s*{[^}]*zoom:/s);
  assert.match(styles, /--font-size-increase:\s*3px/);
  assert.doesNotMatch(styles, /font-size:\s*\d+px/);
  assert.match(styles, /font-size:\s*calc\(14px \+ var\(--font-size-increase\)\)/);
  assert.match(styles, /\.shell\s*{[^}]*min-height:\s*100dvh/s);
  assert.match(styles, /\.sidebar\s*{[^}]*height:\s*100dvh/s);
  assert.match(styles, /\.sidebar nav\s*{[^}]*min-height:\s*0;[^}]*overflow-y:\s*auto/s);
  assert.match(styles, /grid-template-columns:\s*var\(--sidebar-width, 244px\)/);
  assert.match(styles, /\.sidebar nav button\s*{[^}]*min-height:\s*39px;[^}]*height:\s*auto;[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere/s);
});

test("sidebar can be resized with pointer or keyboard", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /const \[sidebarWidth, setSidebarWidth\] = useState\(244\)/);
  assert.match(source, /Math\.min\(420, Math\.max\(190/);
  assert.match(source, /className="sidebar-resizer"/);
  assert.match(source, /onPointerDown=\{startSidebarResize\}/);
  assert.match(source, /onKeyDown=\{resizeSidebarWithKeyboard\}/);
  assert.match(source, /"--sidebar-width": `\$\{sidebarWidth\}px`/);
  assert.match(styles, /\.sidebar-resizer\s*{[^}]*cursor:\s*col-resize;[^}]*touch-action:\s*none/s);
});

test("MFA QR is CSP-compatible for every role", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  const caddy = await readFile(new URL("../deploy/Caddyfile", import.meta.url), "utf8");
  assert.match(source, /<img\s+className="mfa-qr"\s+src=\{mfa\.qr_svg\}/s);
  assert.doesNotMatch(source, /<object\s+className="mfa-qr"/s);
  assert.match(source, /className="login-autofill-sink"\s+name="username"\s+autoComplete="username"/s);
  assert.match(source, /name="totp_code"[\s\S]*ref=\{mfaCodeRef\}[\s\S]*autoComplete="one-time-code"[\s\S]*value=\{mfaCode\}/s);
  assert.match(source, /requestAnimationFrame\(\(\) => mfaCodeRef\.current\?\.focus\(\)\)/);
  assert.match(source, /replace\(\/\\D\/g, ""\)\.slice\(0, 6\)/);
  assert.match(styles, /\.login-autofill-sink\s*\{[^}]*left:\s*-10000px/s);
  assert.match(caddy, /img-src 'self' data: blob:/);
  assert.match(caddy, /script-src-attr 'none'/);
});

test("viewer navigation is permission-aware and stale admin hashes are replaced", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /fetch\("\/api\/v1\/me"/);
  assert.match(source, /permissions:\s*\["users\.manage", "roles\.manage", "ldap\.manage"\]/);
  assert.match(source, /allowedNavigation\.some/);
  assert.match(source, /window\.history\.replaceState\(null, "", sectionRoute\(fallbackSection\)\)/);
  assert.match(source, /Đang tải quyền tài khoản/);
});

test("Linux package is advertised as a self-contained offline installer", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /offline self-contained/);
  assert.match(source, /Ubuntu 22\.04\/24\.04 · Oracle Linux 7\/8 · RHEL 7\/8 · x86_64/);
  assert.match(source, /không cần Python, pip, apt, dnf, yum hoặc Internet/);
});
