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
  assert.match(source, /Kết nối PostgreSQL/);
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
});

test("Windows and Linux fleets can queue OS-aware common tasks", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /Tạo task chung/);
  assert.match(source, /\/api\/v1\/bulk-tasks/);
  assert.match(source, /firewall\.rule\.add\.auto/);
  assert.match(source, /Windows dùng group Administrators theo SID/);
  assert.match(source, /Oracle Linux\/Red Hat chọn default firewalld zone/);
  assert.match(source, /server_ids:\s*servers\.map/);
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
  assert.match(resources, /<span>Thao tác<\/span>/);
  assert.match(resources, /disabled=\{!canExtend\}/);
  assert.match(resources, /partition Recovery hoặc partition khác đang nằm ở giữa/);
  assert.match(resources, /logicalVolumeMapperPath\(item\) === node\.path/);
  assert.match(resources, /Unallocated không thể kéo thả/);
  assert.match(resources, /queue\("storage\.shrink"/);
  assert.match(resources, /Thứ tự vật lý các phân vùng/);
  assert.match(resources, /type === "unallocated"/);
  assert.match(resources, /Shrink không di chuyển phần đang chắn/);
  assert.doesNotMatch(resources, /Windows Update API/);
  assert.doesNotMatch(resources, /Configuration Manager/);
  assert.match(resources, /objectArray\(payload\.updates\)/);
  assert.match(resources, /diagnostics\.currentScanComplete === true/);
  assert.match(resources, /Chưa thể kết luận máy có 0 bản cập nhật/);
  assert.match(resources, /Đang hiển thị dữ liệu hoàn tất gần nhất/);
  assert.match(source, /successfulUpdateScanJobs/);
  assert.match(source, /Chi tiết thao tác/);
  assert.match(source, /Tải thêm nhật ký/);
  assert.match(source, /tự xóa sau \{auditRetentionDays\} ngày/);
});

test("platform users, LDAP assignments and custom roles are editable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /Tạo tài khoản Local/);
  assert.match(source, /Cấu hình LDAP \/ Active Directory/);
  assert.match(source, /đổi role riêng từng user LDAP/);
  assert.match(source, /Roles & quyền hạn/);
  assert.match(source, /permission-groups/);
  assert.match(source, /Groups của trạm vận hành/);
  assert.match(source, /allowed_group_dns/);
  assert.match(source, /Quét groups/);
  assert.match(source, /platform-groups/);
  assert.match(source, /method: "PATCH"/);
  assert.match(source, /method: "DELETE"/);
});

test("process resources and server visibility controls are operable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  assert.match(resources, /cpuPercent/);
  assert.match(resources, /memoryBytes/);
  assert.match(resources, /Realtime 5s/);
  assert.match(resources, /Đã khóa \/ disable/);
  assert.match(resources, /Unlock tài khoản/);
  assert.match(source, /Share \$\{server\.name\}/);
  assert.match(source, /Xóa máy chủ/);
  assert.match(source, /servers\.manage/);
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
