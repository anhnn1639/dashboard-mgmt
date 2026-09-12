"use client";

import Guacamole from "guacamole-common-js";
import { CSSProperties, DragEvent, FormEvent, ReactElement, KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AccountsResourceTab, LogsResourceTab, ModalShell, ProcessesResourceTab, ServicesResourceTab, StorageResourceTab, UpdatesResourceTab } from "./server-resource-tabs";
import { UpdateSourceSettingsView } from "./update-source-settings";
import { RemoteCredentialsView } from "./remote-credentials";
import { ApprovalsView, ReadOnlyWorkspace } from "./role-workspaces";
import { ManagedTargetsView } from "./managed-targets";
import { NotificationCenter } from "./notification-center";

type OSFamily = "linux" | "windows";
type LinuxOfflineProfile = "ubuntu-22.04" | "ubuntu-24.04" | "ol-7" | "ol-8";

const LINUX_OFFLINE_PROFILE_LABELS: Record<LinuxOfflineProfile, string> = {
  "ubuntu-22.04": "Ubuntu 22.04",
  "ubuntu-24.04": "Ubuntu 24.04",
  "ol-7": "Oracle Linux 7",
  "ol-8": "Oracle Linux 8",
};

type Health = "healthy" | "warning" | "critical" | "offline";
type SystemTheme = "light" | "dark";

type SetupStatus = {
  setupRequired: boolean;
  databaseConfigured: boolean;
  databaseConnected: boolean;
  schemaReady: boolean;
  adminExists: boolean;
  secretsReady: boolean;
  dashboardUrl: string;
  setupTokenRequired: boolean;
  status: "ready" | "setup_required";
};

type CurrentUser = {
  id: string;
  username: string;
  displayName: string;
  role: string;
  source: "local" | "ldap";
  mfaEnrolled: boolean;
  permissions: string[];
};

type AuditEventRow = {
  id: string;
  occurredAt: string;
  actor: string;
  action: string;
  target: string;
  result: string;
  sourceIp: string;
  detail: Record<string, unknown>;
};

type Server = {
  id: string;
  name: string;
  osFamily: OSFamily;
  os: string;
  version: string;
  address: string;
  environment: "Production" | "Staging" | "Development";
  health: Health;
  agentVersion: string;
  lastSeen: string;
  cpu: number;
  memory: number;
  disk: number;
  uptime: string;
  updates: number;
  alerts: number;
  services: number;
  owner: string;
  tags: string[];
  tunnelOnline: boolean;
  shares?: { userIds: string[]; groupIds: string[]; count: number };
};

type PlatformGroupRow = { id: string; name: string; description: string; memberIds: string[]; memberCount: number; createdAt: string };

type JobListRow = {
  id: string;
  serverId: string;
  serverName?: string;
  serverAddress?: string;
  action: string;
  status: string;
  risk: string;
  reason: string;
  createdAt: string;
  exitCode?: number | null;
  output?: string;
};

const COOKIE_SESSION_MARKER = "cookie-session";
const CURRENT_DASHBOARD_BUILD = typeof __TRAM_BUILD_ID__ === "string" ? __TRAM_BUILD_ID__ : "development";

// Only publish confirmed product identity. Release and support metadata can be
// added when provided by the publisher; a build check is not a product version.
const PRODUCT = {
  name: "Operation Portal",
  publisher: "AnhNN Entertaiment",
};

const navIcons: Record<string, ReactElement> = {
  overview: <><path d="M4 10.5 12 4l8 6.5" /><path d="M6 10v9h12v-9" /><path d="M10 19v-5h4v5" /></>,
  linux: <><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></>,
  windows: <><path d="M4 6.5 11 5.5v6H4z" /><path d="M13 5.2 20 4v7.5h-7z" /><path d="M4 12.5h7v6L4 17.5z" /><path d="M13 12.5h7V20l-7-1.2z" /></>,
  network: <><rect x="3" y="9" width="18" height="6" rx="2" /><path d="M7 12h.01M11 12h.01M15 12h6" /></>,
  web: <><circle cx="12" cy="12" r="8" /><path d="M4.5 9.5h15M4.5 14.5h15M12 4a14 14 0 0 0 0 16 14 14 0 0 0 0-16" /></>,
  sessions: <><path d="M7 17 17 7" /><path d="M9 7h8v8" /></>,
  jobs: <><circle cx="12" cy="12" r="8" /><path d="M10 9.5 15 12l-5 2.5z" /></>,
  approvals: <path d="M4 12.5 9 17.5 20 6.5" />,
  "configuration-view": <><circle cx="12" cy="12" r="3" /><path d="M19.4 13.5a7.6 7.6 0 0 0 0-3l1.8-1.4-1.9-3.2-2.1.9a7.6 7.6 0 0 0-2.6-1.5L14.3 3H9.7l-.3 2.3a7.6 7.6 0 0 0-2.6 1.5l-2.1-.9-1.9 3.2 1.8 1.4a7.6 7.6 0 0 0 0 3l-1.8 1.4 1.9 3.2 2.1-.9a7.6 7.6 0 0 0 2.6 1.5l.3 2.3h4.6l.3-2.3a7.6 7.6 0 0 0 2.6-1.5l2.1.9 1.9-3.2z" /></>,
  audit: <path d="M4 7h16M4 12h16M4 17h10" />,
  access: <><circle cx="9" cy="9" r="3.2" /><path d="M3.5 19c.6-3 3-4.6 5.5-4.6S13.9 16 14.5 19" /><path d="M16 8h5M16 12h5M16 16h3" /></>,
  "update-settings": <><path d="M12 16V5" /><path d="M8 9l4-4 4 4" /><path d="M5 19h14" /></>,
  "remote-credentials": <path d="M14.5 6.5a4 4 0 1 0-4.3 6.6L5 18.3V21h3l.6-2.2 2.2-.6.6-2.2 2-.5a4 4 0 0 0 1.1-8z" />,
  agents: <><path d="M12 4v10" /><path d="M8 10l4 4 4-4" /><path d="M5 19h14" /></>,
};

function navIcon(id: string) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      {navIcons[id] ?? <circle cx="12" cy="12" r="7" />}
    </svg>
  );
}

const navItems: Array<{ id: string; label: string; group: string; permissions: string[]; count?: number; adminOnly?: boolean }> = [
  { id: "overview", label: "Tổng quan", group: "infrastructure", permissions: ["servers.view"] },
  { id: "linux", label: "Máy chủ Linux", count: 3, group: "infrastructure", permissions: ["servers.view"] },
  { id: "windows", label: "Máy chủ Windows", count: 3, group: "infrastructure", permissions: ["servers.view"] },
  { id: "network", label: "Thiết bị mạng", group: "infrastructure", permissions: ["servers.view"] },
  { id: "web", label: "Web console", group: "infrastructure", permissions: ["servers.view"] },
  { id: "sessions", label: "Phiên truy cập", group: "operations", permissions: ["recordings.view"] },
  { id: "jobs", label: "Công việc", group: "operations", permissions: ["jobs.view"] },
  { id: "approvals", label: "Phê duyệt", group: "operations", permissions: ["deletions.request", "deletions.approve", "recordings.delete"] },
  { id: "configuration-view", label: "Xem cấu hình", group: "operations", permissions: ["configuration.view"] },
  { id: "audit", label: "Nhật ký kiểm toán", group: "operations", permissions: ["audit.view", "recordings.view"] },
  { id: "access", label: "Người dùng & vai trò", group: "administration", permissions: ["users.manage", "roles.manage", "ldap.manage"] },
  { id: "update-settings", label: "Cấu hình cập nhật", group: "administration", permissions: ["updates.manage"] },
  { id: "remote-credentials", label: "Tài khoản xác thực", group: "administration", permissions: ["sessions.launch"], adminOnly: true },
  { id: "agents", label: "Bộ cài Agent", group: "administration", permissions: ["agents.manage"] },
];

function navigationAllowed(item: (typeof navItems)[number], user: CurrentUser | null) {
  if (!user || (item.adminOnly && user.role !== "admin")) return false;
  if (user.role === "connector" && !["linux", "windows", "network", "web"].includes(item.id)) return false;
  if (user.role === "auditor" && item.id !== "audit") return false;
  if (item.id === "configuration-view" && user.role !== "viewer") return false;
  return item.permissions.some((permission) => user.permissions.includes(permission));
}

const healthLabel: Record<Health, string> = {
  healthy: "Ổn định",
  warning: "Cảnh báo",
  critical: "Nguy cấp",
  offline: "Mất kết nối",
};

function themeForSystemTime(value: Date): SystemTheme {
  const hour = value.getHours();
  return hour >= 6 && hour < 18 ? "light" : "dark";
}

function healthPercentages(counts: readonly number[]): number[] {
  const total = counts.reduce((sum, count) => sum + count, 0);
  if (!total) return counts.map(() => 0);
  const exact = counts.map((count) => (count / total) * 100);
  const percentages = exact.map(Math.floor);
  const remainder = 100 - percentages.reduce((sum, value) => sum + value, 0);
  const order = exact
    .map((value, index) => ({ index, fraction: value - percentages[index] }))
    .sort((left, right) => right.fraction - left.fraction || left.index - right.index);
  for (let index = 0; index < remainder; index += 1) percentages[order[index].index] += 1;
  return percentages;
}

function normalizeSearchText(value: unknown) {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .replace(/[đĐ]/g, "d")
    .toLocaleLowerCase("vi-VN")
    .replace(/\s+/g, " ")
    .trim();
}

const auditResultLabels: Record<string, string> = {
  success: "Thành công",
  denied: "Bị từ chối",
  failed: "Thất bại",
  partial: "Một phần",
  cancelled: "Đã hủy",
};

const hiddenAuditDetailKeys = new Set([
  "backend",
  "database",
  "database_url",
  "delivery",
  "framework",
  "reverse_proxy",
  "scanner",
  "storage",
]);

const operationLabels: Record<string, string> = {
  "inventory.collect": "Thu thập thông tin máy chủ",
  "network.list": "Đọc cấu hình mạng",
  "storage.list": "Đọc thông tin ổ đĩa",
  "storage.create": "Tạo phân vùng hoặc volume",
  "storage.extend": "Mở rộng phân vùng hoặc volume",
  "storage.shrink": "Thu nhỏ phân vùng hoặc volume",
  "storage.delete": "Xóa phân vùng hoặc volume",
  "service.list": "Đọc danh sách dịch vụ",
  "service.start": "Khởi động dịch vụ",
  "service.stop": "Dừng dịch vụ",
  "service.restart": "Khởi động lại dịch vụ",
  "user.list": "Đọc danh sách người dùng",
  "user.create": "Tạo người dùng trên máy chủ",
  "user.update": "Cập nhật người dùng trên máy chủ",
  "user.delete": "Xóa người dùng trên máy chủ",
  "user.password.reset": "Đặt lại mật khẩu người dùng",
  "user.enable": "Bật tài khoản người dùng",
  "user.disable": "Vô hiệu hóa người dùng",
  "user.add_group": "Thêm người dùng vào group",
  "group.list": "Đọc danh sách group",
  "group.create": "Tạo group trên máy chủ",
  "group.delete": "Xóa group trên máy chủ",
  "group.remove_user": "Gỡ người dùng khỏi group",
  "firewall.list": "Đọc cấu hình firewall",
  "firewall.rule.add": "Thêm rule firewall",
  "firewall.rule.add.auto": "Thêm rule firewall tự nhận diện hệ điều hành",
  "firewall.rule.remove": "Gỡ rule firewall",
  "firewall.rule.reorder": "Đổi thứ tự rule firewall",
  "process.list": "Đọc danh sách tiến trình",
  "process.kill": "Dừng tiến trình",
  "patch.scan": "Quét bản cập nhật",
  "patch.source.read": "Đọc nguồn cập nhật",
  "patch.source.configure": "Cấu hình nguồn cập nhật",
  "patch.install": "Cài bản cập nhật đã chọn",
  "logs.read": "Đọc nhật ký hệ thống",
  "logs.sources": "Đọc nguồn nhật ký",
  "logs.sources.update": "Cập nhật nguồn nhật ký",
  "file.deliver": "Truyền file an toàn tới máy chủ",
  "system.reboot": "Khởi động lại máy chủ",
  "job.create": "Tạo công việc",
  "job.auto_refresh": "Tự động làm mới dữ liệu",
  "job.interrupted.requeued": "Xếp hàng lại công việc bị gián đoạn",
  "job.legacy_pending.cancelled": "Hủy công việc cũ chưa chạy",
  "agent.enroll": "Đăng ký Agent",
  "agent.package.create": "Tạo bộ cài Agent",
  "agent.package.claim": "Kích hoạt bộ cài Agent",
  "agent.package.os_mismatch": "Từ chối bộ cài sai hệ điều hành",
  "agent.os_family.changed": "Cách ly Agent báo đổi hệ điều hành",
  "agent.certificate.rotate": "Đổi chứng thư Agent",
  "agent.upgrade": "Cập nhật Agent",
  "agent.upgrade.batch.queued": "Xếp hàng cập nhật Agent theo lô",
  "agent.upgrade.download": "Agent tải gói cập nhật",
  "agent.upgrade.confirmed": "Xác nhận Agent đã cập nhật",
  "agent.upgrade.timeout.failed": "Cập nhật Agent quá thời gian chờ",
  "agent.uninstall.policy": "Đồng bộ bảo vệ gỡ Agent",
  "agent.uninstall.policy.queued": "Xếp hàng bảo vệ gỡ Agent",
  "agent.uninstall.protection.update": "Đổi chính sách bảo vệ gỡ Agent",
  "agent.uninstall.denied": "Từ chối gỡ Agent sai mật khẩu",
  "agent.uninstall.authorized": "Cho phép gỡ Agent",
  "agent.uninstall.completed": "Gỡ Agent hoàn tất",
  "agent.uninstall.failed": "Gỡ Agent thất bại",
  "server.initial_scan.queued": "Xếp hàng quét máy chủ lần đầu",
  "server.share.update": "Cập nhật chia sẻ máy chủ",
  "server.delete": "Xóa máy chủ khỏi hệ thống",
  "bulk_task.create": "Tạo công việc hàng loạt",
  "identity.local.create": "Tạo tài khoản Local",
  "identity.user.update": "Cập nhật tài khoản hệ thống",
  "identity.user.delete": "Xóa tài khoản hệ thống",
  "identity.user.groups": "Cập nhật group của tài khoản",
  "identity.self.profile.update": "Tự cập nhật thông tin tài khoản",
  "identity.self.password.change": "Tự thay đổi mật khẩu",
  "identity.mfa.reset": "Reset MFA người dùng",
  "identity.group.create": "Tạo group phân quyền",
  "identity.group.update": "Cập nhật group phân quyền",
  "identity.group.delete": "Xóa group phân quyền",
  "identity.role.create": "Tạo role",
  "identity.role.update": "Cập nhật role",
  "identity.role.delete": "Xóa role",
  "identity.ldap.users.sync": "Đồng bộ người dùng Active Directory",
  "settings.ldap.update": "Cập nhật cấu hình LDAP",
  "settings.recording_retention.update": "Cập nhật thời gian lưu recording",
  "auth.logout": "Đăng xuất và thu hồi phiên",
  "security.authorization.denied": "Từ chối truy cập do thiếu quyền",
  "remote_credential.create": "Tạo tài khoản Remote",
  "remote_credential.update": "Cập nhật tài khoản Remote",
  "remote_credential.delete": "Xóa tài khoản Remote",
  "session.ssh.launch": "Mở phiên SSH",
  "session.web.launch": "Mở phiên Web console",
  "session.web.redirect_blocked": "Chặn chuyển hướng ngoài danh sách",
  "target.web.redirect_discovery": "Tự dò địa chỉ chuyển hướng",
  "session.rdp.launch": "Mở phiên Remote Desktop",
  "session.recording.view": "Xem lại recording",
  "session.recording.delete.request": "Yêu cầu xóa recording",
  "session.recording.delete.approve": "Duyệt xóa recording",
  "session.recording.retention.pruned": "Tự động xóa recording hết hạn",
  "session.tunnel.closed": "Đóng phiên truy cập từ xa",
  "file.upload.clean": "File tải lên đã quét an toàn",
  "file.upload.blocked": "Chặn file tải lên có mã độc",
  "file.upload.scan_failed": "Quét file tải lên thất bại",
  "file.download": "Agent tải file an toàn",
  "file.download.expired": "Từ chối file đã hết hạn",
  "file.download.decrypt_failed": "Giải mã file thất bại",
  "file.payload.expired": "Xóa file truyền đã hết hạn",
  "audit.retention.pruned": "Tự động xóa audit hết hạn",
  "system.dashboard_url.update": "Cập nhật địa chỉ dashboard",
  "system.setup.complete": "Hoàn tất thiết lập hệ thống",
};

function jobActionLabel(action: string) {
  return operationLabels[action] ?? `Thao tác ${action.replaceAll(".", " / ")}`;
}

function auditActionLabel(action: string, detail: Record<string, unknown> = {}) {
  const nestedAction = typeof detail.action === "string"
    ? detail.action
    : typeof detail.refresh_action === "string"
      ? detail.refresh_action
      : "";
  if (action === "job.succeeded") return nestedAction ? `Hoàn tất: ${jobActionLabel(nestedAction)}` : "Công việc hoàn tất";
  if (action === "job.failed") return nestedAction ? `Thất bại: ${jobActionLabel(nestedAction)}` : "Công việc thất bại";
  if (action === "job.create" && nestedAction) return `Tạo công việc: ${jobActionLabel(nestedAction)}`;
  if (action === "job.auto_refresh" && nestedAction) return `Làm mới sau thao tác: ${jobActionLabel(nestedAction)}`;
  return operationLabels[action] ?? jobActionLabel(action);
}

function auditTargetLabel(target: string) {
  return String(target ?? "").trim().toLocaleLowerCase("en-US") === "control-plane" ? "hệ thống" : target;
}

function serverRoute(server: Server) {
  return `#/${server.osFamily}/${encodeURIComponent(server.name)}`;
}

function sectionRoute(section: string) {
  return `#/${section}`;
}

type FirewallRule = {
  id: string;
  backend: "windows" | "ufw" | "firewalld" | "nftables" | "iptables";
  name: string;
  direction: string;
  action: string;
  enabled: boolean;
  protocol: string;
  localPort: string;
  remotePort: string;
  source: string;
  destination: string;
  profile: string;
  raw: string;
  removable: boolean;
  reorderable?: boolean;
  orderGroup?: string;
  managedBy?: string;
  spec: Record<string, unknown>;
};

type FirewallTarget = {
  id: string;
  label: string;
  family: string;
  table: string;
  chain: string;
  direction: "in" | "out";
};

type FirewallCapabilities = {
  profiles: string[];
  activeProfiles: string[];
  zones: string[];
  defaultZone: string;
  targets: FirewallTarget[];
};

type FirewallScan = {
  backend: FirewallRule["backend"] | "";
  backends: string[];
  capabilities: FirewallCapabilities;
  rules: FirewallRule[];
  warning?: string;
};

function parseFirewallOutput(output: string | undefined): FirewallScan {
  const emptyCapabilities: FirewallCapabilities = { profiles: [], activeProfiles: [], zones: [], defaultZone: "", targets: [] };
  if (!output) return { backend: "", backends: [], capabilities: emptyCapabilities, rules: [] };
  try {
    const parsed = JSON.parse(output) as Partial<FirewallScan>;
    const rules = Array.isArray(parsed.rules)
      ? parsed.rules.filter(
          (rule): rule is FirewallRule =>
            Boolean(rule) &&
            typeof rule === "object" &&
            typeof rule.id === "string" &&
            typeof rule.backend === "string",
        )
      : [];
    const rawCapabilities = parsed.capabilities && typeof parsed.capabilities === "object"
      ? parsed.capabilities as Partial<FirewallCapabilities>
      : {};
    const targets = Array.isArray(rawCapabilities.targets)
      ? rawCapabilities.targets.filter(
          (target): target is FirewallTarget =>
            Boolean(target) &&
            typeof target === "object" &&
            typeof target.id === "string" &&
            typeof target.label === "string" &&
            typeof target.family === "string" &&
            typeof target.table === "string" &&
            typeof target.chain === "string" &&
            (target.direction === "in" || target.direction === "out"),
        )
      : [];
    return {
      backend: typeof parsed.backend === "string" ? parsed.backend as FirewallScan["backend"] : "",
      backends: Array.isArray(parsed.backends) ? parsed.backends.map(String) : [],
      capabilities: {
        profiles: Array.isArray(rawCapabilities.profiles) ? rawCapabilities.profiles.map(String) : [],
        activeProfiles: Array.isArray(rawCapabilities.activeProfiles) ? rawCapabilities.activeProfiles.map(String) : [],
        zones: Array.isArray(rawCapabilities.zones) ? rawCapabilities.zones.map(String) : [],
        defaultZone: typeof rawCapabilities.defaultZone === "string" ? rawCapabilities.defaultZone : "",
        targets,
      },
      rules,
      warning: typeof parsed.warning === "string" ? parsed.warning : undefined,
    };
  } catch {
    return { backend: "", backends: [], capabilities: emptyCapabilities, rules: [] };
  }
}

function firewallRuleKey(rule: FirewallRule) {
  return `${rule.backend}:${rule.id}`;
}

function firewallCapabilitiesForForm(scan: FirewallScan): FirewallCapabilities {
  const profiles = scan.capabilities.profiles.length
    ? scan.capabilities.profiles
    : scan.backend === "windows"
      ? ["Any", "Domain", "Private", "Public"]
      : [];
  const zones = scan.capabilities.zones.length
    ? scan.capabilities.zones
    : scan.backend === "firewalld"
      ? Array.from(new Set(scan.rules.map((rule) => rule.profile).filter(Boolean)))
      : [];
  const derivedTargets = new Map<string, FirewallTarget>();
  if (scan.backend === "nftables" || scan.backend === "iptables") {
    for (const rule of scan.rules) {
      const family = String(rule.spec.family ?? "");
      const table = String(rule.spec.table ?? "");
      const chain = String(rule.spec.chain ?? "");
      const normalizedChain = chain.toLowerCase();
      if (!family || table !== "filter" || !["input", "output"].includes(normalizedChain)) continue;
      const direction = normalizedChain === "input" ? "in" : "out";
      const id = `${family}:${table}:${chain}`;
      derivedTargets.set(id, { id, family, table, chain, direction, label: `${family} ${table} → ${chain} (${direction === "in" ? "INPUT" : "OUTPUT"})` });
    }
  }
  return {
    profiles,
    activeProfiles: scan.capabilities.activeProfiles,
    zones,
    defaultZone: scan.capabilities.defaultZone || zones[0] || "",
    targets: scan.capabilities.targets.length ? scan.capabilities.targets : Array.from(derivedTargets.values()),
  };
}

function MiniBar({
  value,
  dangerAt = 85,
}: {
  value: number;
  dangerAt?: number;
}) {
  const tone = value >= dangerAt ? "danger" : value >= 70 ? "warn" : "good";
  return (
    <span className="mini-bar" aria-label={`${value}%`}>
      <i className={tone} style={{ width: `${value}%` }} />
    </span>
  );
}

function ServerTable({
  servers,
  onSelect,
  onShare,
  onDelete,
  selection,
}: {
  servers: Server[];
  onSelect: (server: Server) => void;
  onShare?: (server: Server) => void;
  onDelete?: (server: Server) => void;
  selection?: {
    selectedIds: string[];
    toggle: (serverId: string) => void;
    toggleAll: () => void;
  };
}) {
  const allSelected = Boolean(servers.length) && servers.every((server) => selection?.selectedIds.includes(server.id));
  return (
    <div className="table-scroll">
      <table className="server-table">
        <thead>
          <tr>
            {selection ? <th className="server-select-column"><input type="checkbox" aria-label="Chọn tất cả máy chủ đang hiển thị" checked={allSelected} onChange={selection.toggleAll} /></th> : null}
            <th>Máy chủ</th>
            <th>Hệ điều hành</th>
            <th>Trạng thái</th>
            <th>CPU</th>
            <th>Bộ nhớ</th>
            <th>Ổ đĩa</th>
            <th>Cập nhật</th>
            {onShare ? <th>Share</th> : null}
            <th />
          </tr>
        </thead>
        <tbody>
          {servers.map((server) => (
            <tr
              key={server.id}
              role="button"
              onClick={() => onSelect(server)}
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onSelect(server)}
            >
              {selection ? <td className="server-select-column" onClick={(event) => event.stopPropagation()}><input type="checkbox" aria-label={`Chọn ${server.name}`} checked={selection.selectedIds.includes(server.id)} onChange={() => selection.toggle(server.id)} /></td> : null}
              <td>
                <div className="server-name">
                  <span className={`os-avatar ${server.osFamily}`}>
                    {server.osFamily === "windows" ? "W" : ">_"}
                  </span>
                  <span>
                    <a
                      className="server-link"
                      href={serverRoute(server)}
                      onClick={(event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        onSelect(server);
                      }}
                    >
                      {server.name}
                    </a>
                    <small>
                      {server.address} · {server.environment}
                    </small>
                  </span>
                </div>
              </td>
              <td>
                <strong className="cell-main">{server.os}</strong>
                <small>{server.version}</small>
              </td>
              <td>
                <span className={`status ${server.health}`}>
                  <i />
                  {healthLabel[server.health]}
                </span>
                <small>{server.lastSeen}</small>
              </td>
              <td>
                <span className="metric-value">{server.cpu}%</span>
                <MiniBar value={server.cpu} />
              </td>
              <td>
                <span className="metric-value">{server.memory}%</span>
                <MiniBar value={server.memory} />
              </td>
              <td>
                <span className="metric-value">{server.disk}%</span>
                <MiniBar value={server.disk} dangerAt={90} />
              </td>
              <td>
                <span
                  className={
                    server.updates > 15 ? "update-count hot" : "update-count"
                  }
                >
                  {server.updates}
                </span>
              </td>
              {onShare ? <td><button type="button" className="row-more share-button" onClick={(event) => { event.stopPropagation(); onShare(server); }}>{server.shares?.count ?? 0} user/group</button></td> : null}
              <td>
                <div className="server-row-actions"><button type="button" className="row-more" aria-label={`Mở ${server.name}`} onClick={(e) => { e.stopPropagation(); onSelect(server); }}>•••</button>{onDelete ? <button type="button" className="server-delete-button" aria-label={`Xóa ${server.name}`} title={`Xóa máy chủ ${server.name}`} onClick={(event) => { event.stopPropagation(); onDelete(server); }}>Delete</button> : null}</div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function OpsConsole() {
  const [servers, setServers] = useState<Server[]>([]);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [setupStatusError, setSetupStatusError] = useState("");
  const [token, setToken] = useState("");
  const [authReady, setAuthReady] = useState(false);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [identityReady, setIdentityReady] = useState(true);
  const [identityError, setIdentityError] = useState("");
  const [active, setActive] = useState("overview");
  const [selected, setSelected] = useState<Server | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | Health>("all");
  const [modal, setModal] = useState<"command" | "session" | null>(null);
  const [toast, setToast] = useState("");
  const [loading, setLoading] = useState(true);
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);
  const [bulkTaskOpen, setBulkTaskOpen] = useState(false);
  const [serverManagement, setServerManagement] = useState<{ server: Server; mode: "share" | "delete" } | null>(null);
  const [managedShare, setManagedShare] = useState<{ id: string; name: string } | null>(null);
  const [recentAudit, setRecentAudit] = useState<AuditEventRow[]>([]);
  const [recentAuditBusy, setRecentAuditBusy] = useState(false);
  const [recentAuditError, setRecentAuditError] = useState("");
  const [sidebarWidth, setSidebarWidth] = useState(244);
  const [accountOpen, setAccountOpen] = useState(false);
  const [systemClock, setSystemClock] = useState("--:--:--");
  const [systemTheme, setSystemTheme] = useState<SystemTheme>("dark");
  const [newDashboardBuild, setNewDashboardBuild] = useState("");
  const [dashboardBuildCheck, setDashboardBuildCheck] = useState<"checking" | "current" | "unavailable">(
    CURRENT_DASHBOARD_BUILD === "development" ? "unavailable" : "checking",
  );
  const [aboutOpen, setAboutOpen] = useState(false);
  const aboutDialogRef = useRef<HTMLDialogElement>(null);
  const aboutCloseRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!aboutOpen) return;
    const dialog = aboutDialogRef.current;
    if (!dialog) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialog.showModal();
    aboutCloseRef.current?.focus();
    return () => {
      dialog.close();
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [aboutOpen]);

  function containAboutFocus(event: ReactKeyboardEvent<HTMLDialogElement>) {
    if (event.key !== "Tab") return;
    const controls = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>("button:not([disabled]):not([tabindex='-1'])"));
    const first = controls[0];
    const last = controls.at(-1);
    if (!first || !last) return;
    if (event.shiftKey && (document.activeElement === first || !event.currentTarget.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
  const sidebarResizeRef = useRef<{ pointerId: number; startX: number; startWidth: number } | null>(null);

  useEffect(() => {
    const updateSystemAppearance = () => {
      const current = new Date();
      const nextTheme = themeForSystemTime(current);
      setSystemClock(current.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }));
      setSystemTheme(nextTheme);
      document.documentElement.dataset.theme = nextTheme;
    };
    updateSystemAppearance();
    const timer = window.setInterval(updateSystemAppearance, 1_000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (CURRENT_DASHBOARD_BUILD === "development") return;
    let active = true;
    let checkGeneration = 0;
    let controller: AbortController | null = null;
    const checkDashboardBuild = async () => {
      const generation = ++checkGeneration;
      controller?.abort();
      const requestController = new AbortController();
      controller = requestController;
      const timeout = window.setTimeout(() => requestController.abort(), 10_000);
      try {
        const response = await fetch(`/build-info.json?check=${Date.now()}`, { cache: "no-store", signal: requestController.signal });
        if (!response.ok) throw new Error("Build check unavailable");
        const data = await response.json() as { buildId?: unknown };
        if (typeof data.buildId !== "string" || !data.buildId.trim()) throw new Error("Invalid build information");
        if (!active || generation !== checkGeneration) return;
        setNewDashboardBuild(data.buildId !== CURRENT_DASHBOARD_BUILD ? data.buildId : "");
        setDashboardBuildCheck("current");
      } catch {
        if (active && generation === checkGeneration) setDashboardBuildCheck("unavailable");
      } finally {
        window.clearTimeout(timeout);
      }
    };
    void checkDashboardBuild();
    const timer = window.setInterval(checkDashboardBuild, 60_000);
    const checkWhenVisible = () => {
      if (document.visibilityState === "visible") void checkDashboardBuild();
    };
    document.addEventListener("visibilitychange", checkWhenVisible);
    return () => {
      active = false;
      controller?.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", checkWhenVisible);
    };
  }, []);

  function clampSidebarWidth(width: number) {
    return Math.min(420, Math.max(190, Math.round(width)));
  }

  function startSidebarResize(event: ReactPointerEvent<HTMLDivElement>) {
    sidebarResizeRef.current = { pointerId: event.pointerId, startX: event.clientX, startWidth: sidebarWidth };
    event.currentTarget.setPointerCapture(event.pointerId);
    event.preventDefault();
  }

  function moveSidebarResize(event: ReactPointerEvent<HTMLDivElement>) {
    const resize = sidebarResizeRef.current;
    if (!resize || resize.pointerId !== event.pointerId) return;
    setSidebarWidth(clampSidebarWidth(resize.startWidth + event.clientX - resize.startX));
  }

  function stopSidebarResize(event: ReactPointerEvent<HTMLDivElement>) {
    if (sidebarResizeRef.current?.pointerId !== event.pointerId) return;
    sidebarResizeRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  }

  function resizeSidebarWithKeyboard(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    if (event.key === "Home") return setSidebarWidth(190);
    if (event.key === "End") return setSidebarWidth(420);
    setSidebarWidth((current) => clampSidebarWidth(current + (event.key === "ArrowRight" ? 16 : -16)));
  }
  const loadServers = useCallback(async (showLoading = false) => {
    if (!token) return;
    if (showLoading) setLoading(true);
    try {
      const response = await fetch("/api/v1/servers", {
        headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
      });
      if (response.status === 401) {
        setCurrentUser(null);
        setToken("");
        throw new Error("Unauthorized");
      }
      if (!response.ok) throw new Error("Unable to load servers");
      const data = await response.json();
      if (Array.isArray(data.items)) setServers(data.items);
    } catch {
      // The 15-second background refresh keeps the last known fleet visible on transient failures.
    } finally {
      setLoading(false);
    }
  }, [token]);

  const loadRecentAudit = useCallback(async () => {
    if (!token || !currentUser?.permissions.includes("audit.view")) {
      setRecentAudit([]);
      setRecentAuditError("");
      return;
    }
    setRecentAuditBusy(true);
    setRecentAuditError("");
    try {
      const response = await fetch("/api/v1/audit?limit=6", {
        headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error("Không thể tải hoạt động gần đây");
      const data = await response.json();
      setRecentAudit(Array.isArray(data.items) ? data.items : []);
    } catch (reason) {
      setRecentAuditError(reason instanceof Error ? reason.message : "Không thể tải hoạt động gần đây");
    } finally {
      setRecentAuditBusy(false);
    }
  }, [currentUser, token]);

  useEffect(() => {
    let mounted = true;
    fetch("/api/v1/setup/status", { headers: { Accept: "application/json" } })
      .then((response) =>
        response.ok
          ? response.json()
          : Promise.reject(new Error("Dịch vụ vận hành chưa sẵn sàng")),
      )
      .then((data: SetupStatus) => {
        if (mounted) setSetupStatus(data);
      })
      .catch((reason) => {
        if (mounted)
          setSetupStatusError(
            reason instanceof Error
              ? reason.message
              : "Không thể kiểm tra trạng thái hệ thống",
          );
      });
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setToken(COOKIE_SESSION_MARKER);
      setIdentityReady(false);
      setAuthReady(true);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!authReady || !token) return;
    let mounted = true;
    fetch("/api/v1/me", { headers: { Accept: "application/json", Authorization: `Bearer ${token}` } })
      .then((response) => {
        if (response.status === 401) {
          setCurrentUser(null);
          setIdentityReady(true);
          setToken("");
          throw new Error("Unauthorized");
        }
        return response.ok ? response.json() : Promise.reject(new Error("Không thể đọc quyền của tài khoản"));
      })
      .then((data: CurrentUser) => {
        if (mounted) setCurrentUser({ ...data, permissions: Array.isArray(data.permissions) ? data.permissions : [] });
      })
      .catch((reason) => {
        if (mounted && reason instanceof Error && reason.message !== "Unauthorized") setIdentityError(reason.message);
      })
      .finally(() => {
        if (mounted) setIdentityReady(true);
      });
    return () => { mounted = false; };
  }, [authReady, token]);

  useEffect(() => {
    if (!token || !currentUser?.permissions.includes("servers.view")) return;
    const initial = window.setTimeout(() => void loadServers(), 0);
    const timer = window.setInterval(() => {
      void loadServers();
    }, 15_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [loadServers, token, currentUser]);

  useEffect(() => {
    if (active !== "overview" || !currentUser) return;
    const timer = window.setTimeout(() => void loadRecentAudit(), 0);
    return () => window.clearTimeout(timer);
  }, [active, currentUser, loadRecentAudit]);

  useEffect(() => {
    if (token && !currentUser) return;
    const allowedNavigation = navItems.filter((item) => navigationAllowed(item, currentUser));
    const fallbackSection = allowedNavigation[0]?.id ?? "overview";
    const applyHashRoute = () => {
      const [section, encodedName] = window.location.hash.replace(/^#\/?/, "").split("/");
      if ((section === "linux" || section === "windows") && allowedNavigation.some((item) => item.id === section)) {
        setActive(section);
        if (encodedName) {
          let requestedName = "";
          try {
            requestedName = decodeURIComponent(encodedName);
          } catch {
            setSelected(null);
            return;
          }
          setSelected(
            servers.find(
              (server) => server.osFamily === section && server.name === requestedName,
            ) ?? null,
          );
        } else {
          setSelected(null);
        }
      } else if (allowedNavigation.some((item) => item.id === section)) {
        setActive(section);
        setSelected(null);
      } else {
        setActive(fallbackSection);
        setSelected(null);
        window.history.replaceState(null, "", sectionRoute(fallbackSection));
      }
    };
    applyHashRoute();
    window.addEventListener("hashchange", applyHashRoute);
    window.addEventListener("popstate", applyHashRoute);
    return () => {
      window.removeEventListener("hashchange", applyHashRoute);
      window.removeEventListener("popstate", applyHashRoute);
    };
  }, [servers, token, currentUser]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setModal("command");
      }
      if (event.key === "Escape") {
        setModal(null);
        setBulkTaskOpen(false);
        setSelected(null);
        if (active === "linux" || active === "windows")
          window.history.pushState(null, "", sectionRoute(active));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active]);

  const scope = active === "linux" || active === "windows" ? active : null;
  const visibleNavItems = useMemo(
    () => navItems.filter((item) => navigationAllowed(item, currentUser)),
    [currentUser],
  );
  const infrastructureNavigation = visibleNavItems.filter((item) => item.group === "infrastructure");
  const operationsNavigation = visibleNavItems.filter((item) => item.group === "operations" || (currentUser?.role !== "admin" && item.group === "administration"));
  const administrationNavigation = currentUser?.role === "admin" ? visibleNavItems.filter((item) => item.group === "administration") : [];
  const visibleServers = useMemo(
    () =>
      servers.filter((server) => {
        const matchesOS = !scope || server.osFamily === scope;
        const matchesHealth = filter === "all" || server.health === filter;
        const haystack =
          `${server.name} ${server.address} ${server.os} ${server.version} ${server.tags.join(" ")}`.toLowerCase();
        return (
          matchesOS && matchesHealth && haystack.includes(query.toLowerCase())
        );
      }),
    [servers, scope, filter, query],
  );
  const searchMatches = useMemo(
    () =>
      query.trim()
        ? servers
            .filter((server) =>
              `${server.name} ${server.address} ${server.os} ${server.tags.join(" ")}`
                .toLowerCase()
                .includes(query.trim().toLowerCase()),
            )
            .slice(0, 7)
        : [],
    [servers, query],
  );

  const online = servers.filter((s) => s.health !== "offline").length;
  const availability = servers.length
    ? Math.round((online / servers.length) * 100)
    : 0;
  const warnings = servers.reduce((sum, s) => sum + s.alerts, 0);
  const updates = servers.reduce((sum, s) => sum + s.updates, 0);
  const healthyCount = servers.filter((server) => server.health === "healthy").length;
  const warningCount = servers.filter((server) => server.health === "warning").length;
  const criticalCount = servers.filter((server) => ["critical", "offline"].includes(server.health)).length;
  const [healthyPercent, warningPercent, criticalPercent] = healthPercentages([healthyCount, warningCount, criticalCount]);
  const navCount = (id: string, fallback?: number) =>
    id === "linux"
      ? servers.filter((server) => server.osFamily === "linux").length
      : id === "windows"
        ? servers.filter((server) => server.osFamily === "windows").length
        : fallback;

  function notify(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(""), 3200);
  }

  async function signOut() {
    try {
      const response = await fetch("/api/v1/auth/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok && response.status !== 401) throw new Error("Không thể thu hồi phiên đăng nhập");
      setAccountOpen(false);
      setCurrentUser(null);
      setIdentityReady(true);
      setIdentityError("");
      setToken("");
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể đăng xuất an toàn");
    }
  }

  function openServer(server: Server) {
    if (currentUser?.role === "connector") setModal("session");
    setActive(server.osFamily);
    setSelected(server);
    setSelectedServerIds([]);
    setBulkTaskOpen(false);
    const route = serverRoute(server);
    if (window.location.hash !== route) window.history.pushState(null, "", route);
  }

  function navigateSection(section: string) {
    if (!visibleNavItems.some((item) => item.id === section)) return;
    setActive(section);
    setSelected(null);
    setSelectedServerIds([]);
    setBulkTaskOpen(false);
    window.history.pushState(null, "", sectionRoute(section));
  }

  function closeServer() {
    const section = selected?.osFamily ?? (active === "windows" ? "windows" : "linux");
    setSelected(null);
    window.history.pushState(null, "", sectionRoute(section));
  }

  const title = active === "network" ? "Thiết bị mạng" : active === "web" ? "Web console" : active === "approvals" ? "Phê duyệt" : active === "logs" ? "Log máy chủ" : active === "configuration-view" ? "Xem cấu hình" :
    active === "linux"
      ? "Máy chủ Linux"
      : active === "windows"
        ? "Máy chủ Windows"
        : active === "sessions"
          ? "Phiên truy cập"
          : active === "jobs"
            ? "Công việc vận hành"
            : active === "audit"
              ? "Nhật ký kiểm toán"
              : active === "access"
                ? "Người dùng & vai trò"
                : active === "update-settings"
                  ? "Cấu hình cập nhật"
                  : active === "remote-credentials"
                    ? "Tài khoản xác thực"
                : active === "agents"
                  ? "Tạo bộ cài Agent"
                : "Trung tâm vận hành";

  if (setupStatusError) return <SystemUnavailable message={setupStatusError} />;
  if (!setupStatus || !authReady)
    return <div className="auth-loading">Đang kiểm tra cấu hình hệ thống…</div>;
  if (setupStatus.setupRequired)
    return (
      <SetupScreen
        status={setupStatus}
        onComplete={(dashboardUrl) => {
          setToken("");
          setSetupStatus({
            ...setupStatus,
            setupRequired: false,
            databaseConfigured: true,
            databaseConnected: true,
            schemaReady: true,
            adminExists: true,
            secretsReady: true,
            dashboardUrl,
            status: "ready",
          });
        }}
      />
    );
  if (!token)
    return (
      <LoginScreen
        onLogin={() => {
          setCurrentUser(null);
          setIdentityReady(false);
          setIdentityError("");
          setToken(COOKIE_SESSION_MARKER);
        }}
      />
    );
  if (identityError) return <SystemUnavailable message={identityError} />;
  if (!identityReady || !currentUser)
    return <div className="auth-loading">Đang tải quyền tài khoản…</div>;

  return (
    <main className="shell" style={{ "--sidebar-width": `${sidebarWidth}px` } as CSSProperties}>
      <aside className="sidebar">
        <button
          className="brand"
          onClick={() => navigateSection(visibleNavItems[0]?.id ?? "")}
          aria-label="Về tổng quan"
        >
          <span className="brand-mark">O</span>
          <span>
            <b>Operation</b>
            <small>Portal</small>
          </span>
        </button>
        <nav aria-label="Điều hướng chính">
          {infrastructureNavigation.length > 0 && <p className="nav-heading">HẠ TẦNG</p>}
          {infrastructureNavigation.map((item) => {
            const count = navCount(item.id, item.count);
            return (
              <button
                key={item.id}
                className={active === item.id ? "active" : ""}
                onClick={() => navigateSection(item.id)}
              >
                <span className="nav-icon">{navIcon(item.id)}</span>
                {item.label}
                {count !== undefined && <em>{count}</em>}
              </button>
            );
          })}
          {operationsNavigation.length > 0 && <p className="nav-heading spaced">VẬN HÀNH</p>}
          {operationsNavigation.map((item) => {
            const count = navCount(item.id, item.count);
            return (
              <button
                key={item.id}
                className={active === item.id ? "active" : ""}
                onClick={() => navigateSection(item.id)}
              >
                <span className="nav-icon">{navIcon(item.id)}</span>
                {item.label}
                {count !== undefined && <em>{count}</em>}
              </button>
            );
          })}
          {administrationNavigation.length > 0 && <p className="nav-heading spaced">QUẢN TRỊ</p>}
          {administrationNavigation.map((item) => (
            <button
              key={item.id}
              className={active === item.id ? "active" : ""}
              onClick={() => navigateSection(item.id)}
            >
              <span className="nav-icon">{navIcon(item.id)}</span>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="security-card">
          <div className="security-title">
            <span>◆</span>
            <b>Kết nối được bảo vệ</b>
          </div>
          <p>Kênh quản trị · TLS 1.3</p>
          <div>
            <i />
            CA nội bộ hoạt động
          </div>
        </div>
        <button
          className="profile"
          onClick={() => setAccountOpen(true)}
          title="Mở thông tin tài khoản"
        >
          <span className="profile-avatar">{(currentUser.displayName || currentUser.username).split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("")}</span>
          <span>
            <b>{currentUser.displayName || currentUser.username}</b>
            <small>{currentUser.role} · quản lý tài khoản</small>
          </span>
          <strong>⌄</strong>
        </button>
        <div
          className="sidebar-resizer"
          role="slider"
          tabIndex={0}
          aria-orientation="horizontal"
          aria-label="Thay đổi chiều rộng menu"
          aria-valuemin={190}
          aria-valuemax={420}
          aria-valuenow={sidebarWidth}
          title="Kéo để thay đổi chiều rộng menu"
          onPointerDown={startSidebarResize}
          onPointerMove={moveSidebarResize}
          onPointerUp={stopSidebarResize}
          onPointerCancel={stopSidebarResize}
          onKeyDown={resizeSidebarWithKeyboard}
        />
      </aside>

      <section className="workspace">
        {newDashboardBuild && (
          <aside className="build-update-banner" role="status" aria-live="polite">
            <span><b>Có giao diện mới</b><small>Trang đang mở là bản cũ; tải lại để dùng đầy đủ chức năng vừa triển khai.</small></span>
            <button type="button" onClick={() => window.location.reload()}>Tải lại giao diện</button>
          </aside>
        )}
        <header className="topbar">
          <div className="search">
            <span>⌕</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Tìm máy chủ, IP hoặc nhãn..."
              aria-label="Tìm kiếm"
            />
            {searchMatches.length > 0 && (
              <div className="search-suggestions">
                {searchMatches.map((server) => (
                  <button
                    key={server.id}
                    onClick={() => {
                      openServer(server);
                      setQuery("");
                    }}
                  >
                    <span className={`os-avatar ${server.osFamily}`}>
                      {server.osFamily === "windows" ? "W" : ">_"}
                    </span>
                    <span>
                      <b>{server.name}</b>
                      <small>
                        {server.address} · {server.os}
                      </small>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="top-actions">
            <span className="system-time" role="timer" aria-label={`Giờ hệ thống ${systemClock}`} title="Đồng hồ hệ thống · tự động dùng giao diện sáng từ 06:00 đến 17:59 theo giờ máy quản trị">
              <span aria-hidden="true">{systemTheme === "light" ? "☀" : "◐"}</span>
              <span><b>{systemClock}</b><small>Giờ hệ thống · giao diện {systemTheme === "light" ? "sáng" : "tối"}</small></span>
            </span>
            {currentUser && (
              <NotificationCenter
                key={`${token}:${currentUser.id}:${currentUser.role}:${currentUser.permissions.join(",")}`}
                token={token}
                role={currentUser.role}
                userId={currentUser.id}
                permissions={currentUser.permissions}
                openApprovals={() => navigateSection("approvals")}
                notify={notify}
              />
            )}
            <button
              type="button"
              className="icon-button"
              aria-label={`Giới thiệu ${PRODUCT.name}`}
              aria-expanded={aboutOpen}
              onClick={() => setAboutOpen(true)}
            >
              <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5" /><path d="M12 7.8h.01" /></svg>
              {newDashboardBuild && <span className="about-dot" title="Có bản cập nhật mới" />}
            </button>
          </div>
        </header>

        {aboutOpen && (
          <dialog
            ref={aboutDialogRef}
            className="about-backdrop"
            aria-labelledby="about-title"
            onCancel={(event) => { event.preventDefault(); setAboutOpen(false); }}
            onKeyDown={containAboutFocus}
          >
            <button type="button" className="about-scrim" tabIndex={-1} aria-label="Đóng giới thiệu" onClick={() => setAboutOpen(false)} />
            <div className="about-card">
              <div className="about-top">
                <span className="brand-mark" aria-hidden="true">O</span>
                <div>
                  <h2 id="about-title">{PRODUCT.name}</h2>
                  <p className="about-publisher">{PRODUCT.publisher}</p>
                  <p>Cổng vận hành máy chủ tập trung: truy cập SSH, Remote Desktop và Web console qua một lối vào duy nhất, mọi phiên đều được ghi hình và ghi nhật ký kiểm toán.</p>
                </div>
              </div>
              <div className="about-list">
                <div className="about-row">
                  <span>Cập nhật giao diện</span>
                  {newDashboardBuild
                    ? <span className="status warning"><i />Có bản mới</span>
                    : dashboardBuildCheck === "current"
                      ? <span className="status healthy"><i />Đang dùng bản triển khai hiện tại</span>
                      : <span className="status neutral"><i />{dashboardBuildCheck === "checking" ? "Đang kiểm tra" : "Chưa kiểm tra được"}</span>}
                </div>
              </div>
              <div className="about-foot">
                <small>© {new Date().getFullYear()} {PRODUCT.publisher}</small>
                <span className="inline-actions">
                  {newDashboardBuild && <button type="button" className="button compact" onClick={() => window.location.reload()}>Cập nhật ngay</button>}
                  <button ref={aboutCloseRef} type="button" className="button primary compact" onClick={() => setAboutOpen(false)}>Đóng</button>
                </span>
              </div>
            </div>
          </dialog>
        )}

        <div className="content">
          {!selected && <div className="page-head">
            <div>
              <p className="eyebrow">Operation Portal · AP-SOUTHEAST</p>
              <h1>{title}</h1>
              <p>
                Giám sát, truy cập và thực thi tác vụ an toàn trên toàn bộ máy
                chủ.
              </p>
            </div>
            <div className="head-actions">
              <button
                className="button ghost"
                onClick={() => void loadServers(true)}
                disabled={loading}
              >
                {loading ? "Đang tải…" : "↻ Làm mới"}
              </button>
            </div>
          </div>}

          {!selected && active === "overview" && (
            <>
              <section className="stat-grid" aria-label="Tóm tắt hạ tầng">
                <article className="stat-card">
                  <div className="stat-top">
                    <span className="stat-icon blue">▦</span>
                    <span className="delta good">Đang quản lý</span>
                  </div>
                  <strong>{servers.length}</strong>
                  <h3>Tổng máy chủ</h3>
                  <p>
                    <i className="online-dot" /> {online} đang kết nối
                  </p>
                </article>
                <article className="stat-card">
                  <div className="stat-top">
                    <span className="stat-icon green">✓</span>
                    <span className="delta good">{availability}%</span>
                  </div>
                  <strong>{online}</strong>
                  <h3>Agent trực tuyến</h3>
                  <p>
                    <i className="muted-dot" /> {servers.length - online} mất
                    kết nối
                  </p>
                </article>
                <article className="stat-card">
                  <div className="stat-top">
                    <span className="stat-icon amber">!</span>
                    <span className="delta warn">Cần xử lý</span>
                  </div>
                  <strong>{warnings}</strong>
                  <h3>Cảnh báo đang mở</h3>
                  <p>
                    {servers.filter((s) => s.health === "critical").length} nguy
                    cấp · {servers.filter((s) => s.health === "warning").length}{" "}
                    cảnh báo
                  </p>
                </article>
                <article className="stat-card">
                  <div className="stat-top">
                    <span className="stat-icon violet">↥</span>
                    <span className="delta">Hiện tại</span>
                  </div>
                  <strong>{updates}</strong>
                  <h3>Bản vá chờ cài</h3>
                  <p>
                    {servers.filter((s) => s.updates > 0).length} máy chủ bị ảnh
                    hưởng
                  </p>
                </article>
              </section>

              <section className="overview-grid">
                <article className="panel health-panel">
                  <div className="panel-head">
                    <div>
                      <h2>Sức khỏe hạ tầng</h2>
                      <p>Trạng thái hiện tại của toàn bộ máy chủ</p>
                    </div>
                    <span className="health-sampled-at">Cập nhật {systemClock}</span>
                  </div>
                  <div className="health-chart">
                    <div
                      className={`donut${servers.length ? "" : " empty"}`}
                      role="img"
                      aria-label={`Ổn định ${healthyPercent}%, cảnh báo ${warningPercent}%, nguy cấp hoặc mất kết nối ${criticalPercent}%`}
                      style={
                        {
                          "--healthy-end": `${healthyPercent * 3.6}deg`,
                          "--warning-end": `${(healthyPercent + warningPercent) * 3.6}deg`,
                        } as React.CSSProperties
                      }
                    >
                      <span>
                        <b>{servers.length}</b>
                        <small>máy chủ</small>
                      </span>
                    </div>
                    <div className="health-legend">
                      <div>
                        <i className="green-bg" />
                        <span>
                          Ổn định
                          <small>{healthyCount} máy chủ</small>
                        </span>
                        <b>{healthyPercent}%</b>
                      </div>
                      <div>
                        <i className="amber-bg" />
                        <span>
                          Cảnh báo<small>{warningCount} máy chủ cần theo dõi</small>
                        </span>
                        <b>{warningPercent}%</b>
                      </div>
                      <div>
                        <i className="red-bg" />
                        <span>
                          Nguy cấp / Mất kết nối<small>{criticalCount} máy chủ cần xử lý ngay</small>
                        </span>
                        <b>{criticalPercent}%</b>
                      </div>
                    </div>
                  </div>
                </article>
                <article className="panel activity-panel">
                  <div className="panel-head">
                    <div>
                      <h2>Hoạt động gần đây</h2>
                      <p>Các thao tác mới nhất trong hệ thống</p>
                    </div>
                    {currentUser.permissions.includes("audit.view") && (
                      <button onClick={() => navigateSection("audit")}>
                        Mở nhật ký →
                      </button>
                    )}
                  </div>
                  {!currentUser.permissions.includes("audit.view") ? (
                    <div className="overview-empty compact">
                      <span>≡</span>
                      <b>Role hiện tại không có quyền xem audit</b>
                    </div>
                  ) : recentAuditBusy && recentAudit.length === 0 ? (
                    <div className="overview-empty compact">Đang tải hoạt động…</div>
                  ) : recentAuditError && recentAudit.length === 0 ? (
                    <div className="overview-empty compact">{recentAuditError}</div>
                  ) : recentAudit.length === 0 ? (
                    <div className="overview-empty compact">Chưa có sự kiện audit.</div>
                  ) : (
                    <div className="overview-activity-list">
                      {recentAudit.map((event) => (
                        <button key={event.id} type="button" onClick={() => navigateSection("audit")}>
                          <span className={`overview-activity-result ${event.result || "success"}`} />
                          <span>
                            <b title={event.action}>{auditActionLabel(event.action, event.detail)}</b>
                            <small>{event.actor || "system"} · {auditTargetLabel(event.target) || "hệ thống"}</small>
                          </span>
                          <time>{new Date(event.occurredAt).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" })}</time>
                        </button>
                      ))}
                    </div>
                  )}
                </article>
              </section>
            </>
          )}

          {active === "network" || active === "web" ? <ManagedTargetsView key={active} kind={active} token={token} role={currentUser.role} notify={notify} share={setManagedShare} /> : selected && currentUser.role === "connector" ? <section className="panel view-panel"><h2>{selected.name}</h2><button className="button primary" onClick={() => setModal("session")}>Kết nối</button></section> : selected ? (
            <ServerDrawer
              server={selected}
              close={closeServer}
              openSession={() => setModal("session")}
              notify={notify}
              token={token}
              canConfigureLogs={currentUser.permissions.includes("logs.configure")}
              permissions={currentUser.permissions}
              readOnly={currentUser.role === "viewer"}
            />
          ) : active === "approvals" ? <ApprovalsView token={token} currentUser={currentUser} /> : active === "logs" || active === "configuration-view" ? <ReadOnlyWorkspace key={active} token={token} kind={active === "logs" ? "logs" : "configuration"} /> : active === "sessions" ? (
            <SessionsView token={token} />
          ) : active === "jobs" ? (
            <JobsView token={token} servers={servers} />
          ) : active === "audit" ? (
            <AuditView token={token} />
          ) : active === "access" ? (
            <AccessView token={token} currentUser={currentUser} />
          ) : active === "update-settings" ? (
            <UpdateSourceSettingsView servers={servers} token={token} notify={notify} openJobs={() => navigateSection("jobs")} />
          ) : active === "remote-credentials" ? (
            <RemoteCredentialsView servers={servers} token={token} notify={notify} />
          ) : active === "agents" ? (
            <AgentPackagesView token={token} canManageUninstallProtection={currentUser.role === "admin"} />
          ) : (
            <section className="panel fleet-panel">
              <div className="panel-head fleet-head">
                <div>
                  <h2>
                    {scope
                      ? `Danh sách ${scope === "linux" ? "Linux" : "Windows"}`
                      : "Toàn bộ máy chủ"}
                  </h2>
                  <p>
                    {visibleServers.length} máy chủ · dữ liệu agent theo thời
                    gian thực
                  </p>
                </div>
                <div className="fleet-head-actions">
                  {scope && currentUser.permissions.some((p) => ["updates.manage", "firewall.manage", "accounts.manage"].includes(p)) ? <button type="button" className="button primary compact" onClick={() => setBulkTaskOpen(true)}>＋ Tạo task chung</button> : null}
                  <div className="filters">
                    <button
                      className={filter === "all" ? "active" : ""}
                      onClick={() => setFilter("all")}
                    >
                      Tất cả
                    </button>
                    <button
                      className={filter === "healthy" ? "active" : ""}
                      onClick={() => setFilter("healthy")}
                    >
                      Ổn định
                    </button>
                    <button
                      className={filter === "warning" ? "active" : ""}
                      onClick={() => setFilter("warning")}
                    >
                      Cảnh báo
                    </button>
                    <button
                      className={filter === "critical" ? "active" : ""}
                      onClick={() => setFilter("critical")}
                    >
                      Nguy cấp
                    </button>
                  </div>
                </div>
              </div>
              {scope ? <div className="fleet-selection-bar"><span><b>{selectedServerIds.length}</b> máy đã chọn cho tác vụ hàng loạt</span><button type="button" onClick={() => setSelectedServerIds([])} disabled={!selectedServerIds.length}>Bỏ chọn</button></div> : null}
              {loading ? <div className="loading-line" /> : null}
              <ServerTable
                servers={visibleServers}
                onSelect={openServer}
                onShare={currentUser.role === "admin" && currentUser.permissions.includes("servers.manage") ? (server) => setServerManagement({ server, mode: "share" }) : undefined}
                onDelete={scope && ["admin", "operator"].includes(currentUser.role) && currentUser.permissions.includes("servers.manage") ? (server) => setServerManagement({ server, mode: "delete" }) : undefined}
                selection={scope ? {
                  selectedIds: selectedServerIds,
                  toggle: (serverId) => setSelectedServerIds((current) => current.includes(serverId) ? current.filter((id) => id !== serverId) : [...current, serverId]),
                  toggleAll: () => setSelectedServerIds((current) => visibleServers.every((server) => current.includes(server.id)) ? current.filter((id) => !visibleServers.some((server) => server.id === id)) : Array.from(new Set([...current, ...visibleServers.map((server) => server.id)]))),
                } : undefined}
              />
            </section>
          )}
        </div>
      </section>

      {modal === "session" && selected && (
        <SessionModal
          close={() => setModal(null)}
          notify={notify}
          server={selected}
          token={token}
          isAdmin={currentUser.role === "admin"}
          manageCredentials={() => {
            setModal(null);
            navigateSection("remote-credentials");
          }}
        />
      )}
      {modal === "command" && (
        <CommandPalette
          close={() => setModal(null)}
          servers={servers}
          select={(server) => {
            openServer(server);
            setModal(null);
          }}
        />
      )}
      {bulkTaskOpen && scope && (
        <BulkTaskModal
          close={() => setBulkTaskOpen(false)}
          initialServerIds={selectedServerIds}
          openJobs={() => {
            setBulkTaskOpen(false);
            navigateSection("jobs");
          }}
          notify={notify}
          scope={scope}
          servers={servers.filter((server) => server.osFamily === scope)}
          token={token}
        />
      )}
      {serverManagement?.mode === "share" && <ServerShareModal server={serverManagement.server} token={token} close={() => setServerManagement(null)} saved={(shares) => { setServers((current) => current.map((server) => server.id === serverManagement.server.id ? { ...server, shares } : server)); setServerManagement(null); notify("Đã cập nhật phạm vi nhìn thấy máy chủ."); }} />}
      {managedShare && <ServerShareModal server={managedShare} token={token} close={() => setManagedShare(null)} saved={() => { setManagedShare(null); notify("Đã cập nhật chia sẻ kết nối."); }} />}
      {serverManagement?.mode === "delete" && <ServerDeleteModal server={serverManagement.server} token={token} approvalRequired={currentUser.role === "operator"} close={() => setServerManagement(null)} deleted={(pending) => { if (!pending) { setServers((current) => current.filter((server) => server.id !== serverManagement.server.id)); setSelectedServerIds((current) => current.filter((id) => id !== serverManagement.server.id)); } setServerManagement(null); notify(pending ? "Đã gửi yêu cầu xóa; máy chủ vẫn giữ nguyên cho đến khi một Administrator duyệt." : "Đã xóa máy chủ khỏi danh sách và ngừng chấp nhận Agent cũ."); }} />}
      {accountOpen && <AccountSettingsModal user={currentUser} token={token} close={() => setAccountOpen(false)} signOut={signOut} updated={(nextUser) => { setCurrentUser(nextUser); notify("Đã cập nhật thông tin tài khoản."); }} />}
      {toast && (
        <div className="toast">
          <span>✓</span>
          {toast}
        </div>
      )}
    </main>
  );
}

function AccountSettingsModal({
  user,
  token,
  close,
  signOut,
  updated,
}: {
  user: CurrentUser;
  token: string;
  close: () => void;
  signOut: () => void | Promise<void>;
  updated: (user: CurrentUser) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [messageError, setMessageError] = useState(false);
  const isLocal = user.source === "local";

  function showResult(text: string, error = false) {
    setMessage(text);
    setMessageError(error);
  }

  async function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    showResult("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/me/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ display_name: form.get("display_name") }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? "Không thể cập nhật thông tin tài khoản");
      updated(data as CurrentUser);
      showResult("Đã lưu tên hiển thị. Role và tên đăng nhập không bị thay đổi.");
    } catch (reason) {
      showResult(reason instanceof Error ? reason.message : "Không thể cập nhật thông tin tài khoản", true);
    } finally {
      setBusy(false);
    }
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const newPassword = String(form.get("new_password") ?? "");
    if (newPassword !== String(form.get("confirm_password") ?? "")) {
      showResult("Mật khẩu mới và ô xác nhận chưa khớp.", true);
      return;
    }
    setBusy(true);
    showResult("");
    try {
      const response = await fetch("/api/v1/me/password", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ current_password: form.get("current_password"), new_password: newPassword }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? "Không thể thay đổi mật khẩu");
      formElement.reset();
      showResult("Đã thay đổi mật khẩu. Phiên hiện tại vẫn được giữ; lần đăng nhập sau hãy dùng mật khẩu mới.");
    } catch (reason) {
      showResult(reason instanceof Error ? reason.message : "Không thể thay đổi mật khẩu", true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <ModalShell
      title="Thông tin tài khoản"
      subtitle="Tự quản lý thông tin cơ bản và bảo mật; role chỉ do Administrator phân quyền"
      close={close}
      className="account-settings-modal"
    >
      <div className="account-settings">
        <dl className="account-identity-summary">
          <div><dt>Tên đăng nhập</dt><dd>{user.username}</dd></div>
          <div><dt>Nguồn tài khoản</dt><dd>{isLocal ? "Local" : "Active Directory"}</dd></div>
          <div><dt>Role</dt><dd>{user.role}</dd></div>
          <div><dt>MFA</dt><dd>{user.mfaEnrolled ? "Đang hoạt động" : "Chờ đăng ký"}</dd></div>
        </dl>
        {message && <p className={`settings-message${messageError ? " error" : ""}`}>{message}</p>}
        {isLocal ? (
          <>
            <form className="resource-form account-settings-section" onSubmit={saveProfile}>
              <div className="account-settings-heading"><div><h3>Thông tin cơ bản</h3><p>Username và role không thể tự thay đổi.</p></div></div>
              <label>Tên hiển thị<input name="display_name" defaultValue={user.displayName} minLength={1} maxLength={160} required /></label>
              <div className="modal-actions"><button className="button primary" disabled={busy}>Lưu thông tin</button></div>
            </form>
            <form className="resource-form account-settings-section" onSubmit={changePassword}>
              <div className="account-settings-heading"><div><h3>Thay đổi mật khẩu</h3><p>Phải nhập đúng mật khẩu hiện tại; mật khẩu mới tối thiểu 14 ký tự.</p></div></div>
              <label>Mật khẩu hiện tại<input name="current_password" type="password" autoComplete="current-password" required /></label>
              <div className="resource-form-grid">
                <label>Mật khẩu mới<input name="new_password" type="password" autoComplete="new-password" minLength={14} maxLength={1024} required /></label>
                <label>Xác nhận mật khẩu mới<input name="confirm_password" type="password" autoComplete="new-password" minLength={14} maxLength={1024} required /></label>
              </div>
              <div className="modal-actions"><button className="button primary" disabled={busy}>Đổi mật khẩu</button></div>
            </form>
          </>
        ) : (
          <div className="resource-help">Tên hiển thị và mật khẩu của tài khoản AD được quản lý tại Active Directory. Website chỉ hiển thị các thông tin đã đồng bộ; role vẫn do Administrator của Operation Portal phân quyền.</div>
        )}
        <div className="account-session-actions"><span>Muốn kết thúc phiên làm việc trên thiết bị này?</span><button type="button" className="button danger" onClick={signOut}>Đăng xuất</button></div>
      </div>
    </ModalShell>
  );
}

function ServerShareModal({ server, token, close, saved }: { server: Pick<Server, "id" | "name"> & Partial<Pick<Server, "shares">>; token: string; close: () => void; saved: (shares: { userIds: string[]; groupIds: string[]; count: number }) => void }) {
  const [users, setUsers] = useState<Array<{ id: string; username: string; displayName: string; enabled: boolean }>>([]);
  const [groups, setGroups] = useState<PlatformGroupRow[]>([]);
  const [userIds, setUserIds] = useState<string[]>(server.shares?.userIds ?? []);
  const [groupIds, setGroupIds] = useState<string[]>(server.shares?.groupIds ?? []);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    const headers = { Authorization: `Bearer ${token}` };
    Promise.all([fetch("/api/v1/users", { headers }), fetch("/api/v1/platform-groups", { headers })])
      .then(async ([usersResponse, groupsResponse]) => {
        if (!usersResponse.ok || !groupsResponse.ok) throw new Error("Không thể đọc user/group để chia sẻ");
        setUsers((await usersResponse.json()).items ?? []);
        setGroups((await groupsResponse.json()).items ?? []);
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Không thể tải dữ liệu share"))
      .finally(() => setBusy(false));
  }, [token]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const response = await fetch(`/api/v1/servers/${server.id}/shares`, { method: "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ user_ids: userIds, group_ids: groupIds }) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) saved({ userIds: data.userIds ?? [], groupIds: data.groupIds ?? [], count: Number(data.count ?? 0) });
    else { setError(data.detail ?? "Không thể cập nhật share"); setBusy(false); }
  }
  return <ModalShell title={`Share ${server.name}`} subtitle="Admin, Operator và Viewer thấy toàn bộ. Connector chỉ thấy tài nguyên được chia sẻ trực tiếp hoặc qua group." close={close}><form className="resource-form" onSubmit={submit}>{error && <div className="danger-panel">{error}</div>}<div className="share-picker"><fieldset><legend>Người dùng</legend>{users.filter((user) => user.enabled).map((user) => <label key={user.id} aria-label={`Share cho ${user.username}`}><input type="checkbox" checked={userIds.includes(user.id)} onChange={() => setUserIds((current) => current.includes(user.id) ? current.filter((id) => id !== user.id) : [...current, user.id])} /><span><b>{user.displayName || user.username}</b><small>{user.username}</small></span></label>)}</fieldset><fieldset><legend>Groups của trạm vận hành</legend>{groups.map((group) => <label key={group.id} aria-label={`Share cho group ${group.name}`}><input type="checkbox" checked={groupIds.includes(group.id)} onChange={() => setGroupIds((current) => current.includes(group.id) ? current.filter((id) => id !== group.id) : [...current, group.id])} /><span><b>{group.name}</b><small>{group.memberCount} thành viên</small></span></label>)}</fieldset></div><div className="resource-help">Không chọn ai nghĩa là Connector không nhìn thấy tài nguyên này; Admin, Operator và Viewer vẫn thấy.</div><div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button primary" disabled={busy}>{busy ? "Đang xử lý…" : "Lưu share"}</button></div></form></ModalShell>;
}

function ServerDeleteModal({ server, token, close, deleted, approvalRequired }: { server: Server; token: string; close: () => void; deleted: (pending: boolean) => void; approvalRequired: boolean }) {
  const [confirmation, setConfirmation] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const response = await fetch(`/api/v1/servers/${server.id}`, { method: "DELETE", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ confirmation, reason }) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) deleted(data.status === "pending_approval"); else { setError(data.detail ?? "Không thể xóa máy chủ"); setBusy(false); }
  }
  return <ModalShell title={`Xóa ${server.name}`} subtitle="Máy chủ biến mất khỏi fleet và certificate Agent hiện tại bị từ chối; lịch sử audit/job vẫn được giữ" close={close}><form className="resource-form" onSubmit={submit}>{error && <div className="danger-panel">{error}</div>}<label>Lý do<input value={reason} onChange={(event) => setReason(event.target.value)} minLength={3} maxLength={500} required /></label><label>Gõ <b>DELETE</b><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="off" /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button danger" disabled={busy || confirmation !== "DELETE" || reason.trim().length < 3}>{approvalRequired ? "Gửi yêu cầu xóa" : "Xóa máy chủ"}</button></div></form></ModalShell>;
}

type BulkTaskResponse = {
  id: string;
  targetCount: number;
  items: Array<{ serverId: string; serverName: string; jobId: string; status: string }>;
};

type BulkUpdateCatalog = {
  ready: boolean;
  osFamily: OSFamily;
  osName: string;
  osVersion: string;
  architecture: string;
  servers: Array<{ id: string; name: string; scanStatus: string; scanAt?: string; updateCount: number }>;
  updates: Array<{ id: string; name: string; version: string; repository: string; severity: string; architecture: string; kb: string[]; availableOn: number }>;
};

const firewallPresets = {
  ssh: { name: "Cho phép SSH", protocol: "tcp", port: "22" },
  http: { name: "Cho phép HTTP", protocol: "tcp", port: "80" },
  https: { name: "Cho phép HTTPS", protocol: "tcp", port: "443" },
  dns: { name: "Cho phép DNS", protocol: "udp", port: "53" },
  rdp: { name: "Cho phép Remote Desktop", protocol: "tcp", port: "3389" },
  custom: { name: "", protocol: "tcp", port: "" },
} as const;

function BulkTaskModal({
  close,
  initialServerIds,
  notify,
  openJobs,
  scope,
  servers,
  token,
}: {
  close: () => void;
  initialServerIds: string[];
  notify: (message: string) => void;
  openJobs: () => void;
  scope: OSFamily;
  servers: Server[];
  token: string;
}) {
  const groups = useMemo(() => {
    const result = new Map<string, { key: string; label: string; servers: Server[] }>();
    for (const server of servers) {
      const key = `${encodeURIComponent(server.os)}::${encodeURIComponent(server.version)}`;
      const group = result.get(key) ?? { key, label: `${server.os} · ${server.version || "không rõ version"}`, servers: [] };
      group.servers.push(server);
      result.set(key, group);
    }
    return [...result.values()].sort((left, right) => left.label.localeCompare(right.label, "vi"));
  }, [servers]);
  const preferredServer = servers.find((server) => initialServerIds.includes(server.id));
  const preferredGroup = groups.find((group) => group.servers.some((server) => server.id === preferredServer?.id)) ?? groups[0];
  const [action, setAction] = useState<"user.create" | "firewall.rule.add.auto" | "patch.install">("patch.install");
  const [step, setStep] = useState<1 | 2>(1);
  const [groupKey, setGroupKey] = useState(preferredGroup?.key ?? "");
  const [targetIds, setTargetIds] = useState<string[]>(() => {
    const preferred = preferredGroup?.servers.filter((server) => initialServerIds.includes(server.id)).map((server) => server.id) ?? [];
    return preferred.length ? preferred : (preferredGroup?.servers.map((server) => server.id) ?? []);
  });
  const [catalog, setCatalog] = useState<BulkUpdateCatalog | null>(null);
  const [selectedUpdates, setSelectedUpdates] = useState<string[]>([]);
  const [preset, setPreset] = useState<keyof typeof firewallPresets>(scope === "windows" ? "rdp" : "ssh");
  const [firewallName, setFirewallName] = useState<string>(firewallPresets[scope === "windows" ? "rdp" : "ssh"].name);
  const [firewallProtocol, setFirewallProtocol] = useState<string>(firewallPresets[scope === "windows" ? "rdp" : "ssh"].protocol);
  const [firewallPort, setFirewallPort] = useState<string>(firewallPresets[scope === "windows" ? "rdp" : "ssh"].port);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<BulkTaskResponse | null>(null);
  const formId = "bulk-task-form";
  const selectedGroup = groups.find((group) => group.key === groupKey) ?? groups[0];
  const targetServers = servers.filter((server) => targetIds.includes(server.id));

  function toggleTarget(serverId: string) {
    setTargetIds((current) => current.includes(serverId) ? current.filter((id) => id !== serverId) : [...current, serverId]);
    setCatalog(null);
    setSelectedUpdates([]);
  }

  function changeGroup(value: string) {
    const group = groups.find((item) => item.key === value);
    setGroupKey(value);
    setTargetIds(group?.servers.map((server) => server.id) ?? []);
    setCatalog(null);
    setSelectedUpdates([]);
    setStep(1);
  }

  function applyPreset(value: keyof typeof firewallPresets) {
    const selectedPreset = firewallPresets[value];
    setPreset(value);
    setFirewallName(selectedPreset.name);
    setFirewallProtocol(selectedPreset.protocol);
    setFirewallPort(selectedPreset.port);
  }

  async function loadUpdateCatalog() {
    if (!targetIds.length) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/v1/bulk-update/catalog", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ os_family: scope, server_ids: targetIds }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? "Không thể đọc catalog cập nhật chung");
      setCatalog(data as BulkUpdateCatalog);
      setSelectedUpdates([]);
      setStep(2);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể đọc catalog cập nhật chung");
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const parameters = action === "user.create"
      ? {
          username: String(form.get("username") ?? "").trim(),
          password: String(form.get("password") ?? ""),
          is_admin: form.get("is_admin") === "on",
        }
      : action === "firewall.rule.add.auto" ? {
          name: firewallName.trim(),
          direction: scope === "linux" ? "in" : String(form.get("direction") ?? "in"),
          action: String(form.get("rule_action") ?? "allow"),
          protocol: firewallProtocol,
          local_port: Number(firewallPort),
          remote_port: String(form.get("remote_port") ?? "any").trim() || "any",
          source: String(form.get("source") ?? "any").trim() || "any",
          destination: String(form.get("destination") ?? "any").trim() || "any",
          family: String(form.get("family") ?? "ipv4"),
        } : {
          updates: (catalog?.updates ?? [])
            .filter((update) => selectedUpdates.includes(`${update.id}\u0000${update.version}`))
            .map((update) => ({ id: update.id, version: update.version })),
        };
    try {
      const response = await fetch("/api/v1/bulk-tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          os_family: scope,
          server_ids: targetIds,
          action,
          parameters,
          reason: String(form.get("reason") ?? "").trim(),
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? "Không thể tạo task chung");
      setResult(data as BulkTaskResponse);
      notify(`Đã xếp hàng ${targetIds.length} job trong task chung`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể tạo task chung");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return <ModalShell
      title="Task chung đã được tạo"
      subtitle={`Mã ${result.id.slice(0, 8)} · ${result.targetCount} công việc đã được ghi nhận`}
      close={close}
      className="bulk-task-modal"
      footer={<><button type="button" className="button ghost" onClick={close}>Đóng</button><button type="button" className="button primary" onClick={openJobs}>Xem công việc</button></>}
    >
      <div className="bulk-task-result">
        <div className="resource-help">Mỗi máy chủ nhận một công việc riêng. Máy đang mất kết nối sẽ giữ trạng thái chờ và tiếp tục khi kết nối lại.</div>
        <div className="bulk-target-list">{result.items.map((item) => <div key={item.jobId}><span><b>{item.serverName}</b><small>Job {item.jobId.slice(0, 8)}</small></span><em>{item.status === "queued" ? "Đang chờ Agent" : item.status}</em></div>)}</div>
      </div>
    </ModalShell>;
  }

  return <ModalShell
    title="Tạo task chung"
    subtitle={`${scope === "windows" ? "Windows" : "Linux"} · chọn task, OS/version và máy chủ đích`}
    close={close}
    className="bulk-task-modal"
    footer={action === "patch.install" && step === 1
      ? <><button type="button" className="button ghost" onClick={close}>Hủy</button><button type="button" className="button primary" disabled={busy || !targetIds.length} onClick={() => void loadUpdateCatalog()}>{busy ? "Đang đọc catalog…" : "Tiếp: Chọn patch"}</button></>
      : <><button type="button" className="button ghost" onClick={action === "patch.install" ? () => { setStep(1); setCatalog(null); setSelectedUpdates([]); } : close}>{action === "patch.install" ? "Quay lại" : "Hủy"}</button><button type="submit" form={formId} className="button primary" disabled={busy || !targetIds.length || (action === "patch.install" && (!catalog?.ready || !selectedUpdates.length))}>{busy ? "Đang tạo..." : `Tạo ${targetIds.length} job`}</button></>}
  >
    <form id={formId} className="resource-form bulk-task-form" onSubmit={submit}>
      <label>Loại tác vụ
        <select value={action} disabled={action === "patch.install" && step === 2} onChange={(event) => { setAction(event.target.value as typeof action); setStep(1); setCatalog(null); setSelectedUpdates([]); setError(""); }}>
          <option value="patch.install">Cập nhật bản vá theo OS + version</option>
          <option value="user.create">Tạo user local trên nhiều máy</option>
          <option value="firewall.rule.add.auto">Thêm firewall rule trên nhiều máy</option>
        </select>
      </label>
      {action === "patch.install" ? <>
        <div className="bulk-update-steps"><span className={step === 1 ? "active" : "done"}>1 · OS/version & máy chủ</span><span className={step === 2 ? "active" : ""}>2 · Chọn patch & cập nhật</span></div>
        {step === 1 ? <>
          <label>OS + version<select value={groupKey} onChange={(event) => changeGroup(event.target.value)}>{groups.map((group) => <option key={group.key} value={group.key}>{group.label} · {group.servers.length} máy</option>)}</select></label>
          <fieldset><legend>Máy chủ cùng OS/version</legend><div className="bulk-target-list selectable">{(selectedGroup?.servers ?? []).map((server) => <label key={server.id}><input type="checkbox" checked={targetIds.includes(server.id)} onChange={() => toggleTarget(server.id)} /><span><b>{server.name}</b><small>{server.os} {server.version}</small></span><em className={server.health}>{server.health === "offline" ? "Chờ kết nối" : "Sẵn sàng"}</em></label>)}</div></fieldset>
          <div className="resource-help">Bước tiếp theo chỉ hiển thị patch đang khả dụng trên tất cả máy đã chọn. Windows dùng Update ID/revision do WUA xác nhận cho từng host; Linux dùng đúng repository của release hiện tại.</div>
        </> : <>
          <div className="resource-help"><b>{catalog?.osName} {catalog?.osVersion}</b>{catalog?.architecture ? ` · ${catalog.architecture}` : ""} · {targetServers.length} máy chủ</div>
          {!catalog?.ready ? <div className="danger-panel">Có máy chưa có lần quét cập nhật hoàn tất. Hãy quét lại máy đó rồi tải lại catalog.</div> : null}
          <div className="bulk-target-list compact">{catalog?.servers.map((server) => <div key={server.id}><span><b>{server.name}</b><small>{server.scanAt ? new Date(server.scanAt).toLocaleString("vi-VN") : "Chưa quét"}</small></span><em>{server.scanStatus === "complete" ? `${server.updateCount} gói` : server.scanStatus}</em></div>)}</div>
          <fieldset><legend>Patch chung cho toàn bộ máy đã chọn</legend><div className="bulk-update-list">{catalog?.updates.map((update) => { const key = `${update.id}\u0000${update.version}`; return <label key={key}><input type="checkbox" checked={selectedUpdates.includes(key)} onChange={() => setSelectedUpdates((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key])} /><span><b>{update.name}</b><small>{update.version || "—"} · {update.repository || "nguồn hệ điều hành"}</small></span><em>{update.severity}</em></label>; })}{catalog?.ready && !catalog.updates.length ? <div className="empty-state">Không có patch chung đang chờ trên tất cả máy đã chọn.</div> : null}</div></fieldset>
        </>}
      </> : <fieldset><legend>Máy chủ đích</legend><div className="bulk-target-list selectable">{servers.map((server) => <label key={server.id}><input type="checkbox" checked={targetIds.includes(server.id)} onChange={() => toggleTarget(server.id)} /><span><b>{server.name}</b><small>{server.os} {server.version}</small></span><em className={server.health}>{server.health === "offline" ? "Chờ kết nối" : "Sẵn sàng"}</em></label>)}</div></fieldset>}
      {action === "user.create" ? <>
        <div className="form-grid">
          <label>Username<input name="username" required maxLength={scope === "windows" ? 20 : 32} pattern={scope === "windows" ? "[^\\/\\[\\]:;|=,+*?<>@]{1,20}" : "[a-z_][a-z0-9_.-]{0,31}"} title={scope === "windows" ? "Tên local Windows tối đa 20 ký tự" : "Linux dùng chữ thường, số, _, . hoặc -"} /></label>
          <label>Mật khẩu ban đầu<input name="password" type="password" minLength={12} maxLength={1024} autoComplete="new-password" required /></label>
        </div>
        <label className="check"><input name="is_admin" type="checkbox" /> Cấp quyền quản trị hệ điều hành</label>
        <div className="resource-help">Agent đọc group thật trên từng máy ngay trước khi tạo: Windows dùng group Administrators theo SID, Ubuntu dùng sudo, Oracle Linux/Red Hat dùng wheel. Không truyền tên group đoán từ trình duyệt.</div>
      </> : action === "firewall.rule.add.auto" ? <>
        <div className="form-grid">
          <label>Mẫu cấu hình<select value={preset} onChange={(event) => applyPreset(event.target.value as keyof typeof firewallPresets)}><option value="ssh">SSH · TCP 22</option><option value="rdp">Remote Desktop · TCP 3389</option><option value="http">HTTP · TCP 80</option><option value="https">HTTPS · TCP 443</option><option value="dns">DNS · UDP 53</option><option value="custom">Tùy chỉnh</option></select></label>
          <label>Tên rule<input value={firewallName} onChange={(event) => setFirewallName(event.target.value)} maxLength={128} required /></label>
        </div>
        <div className="form-grid">
          <label>Hướng<select name="direction" defaultValue="in" disabled={scope === "linux"}><option value="in">Inbound</option>{scope === "windows" ? <option value="out">Outbound</option> : null}</select></label>
          <label>Hành động<select name="rule_action" defaultValue="allow"><option value="allow">Allow</option><option value="deny">Block / Drop</option>{scope === "linux" ? <option value="reject">Reject</option> : null}</select></label>
        </div>
        <div className="form-grid">
          <label>Protocol<select value={firewallProtocol} onChange={(event) => setFirewallProtocol(event.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <label>Local port<input type="number" min={1} max={65535} value={firewallPort} onChange={(event) => setFirewallPort(event.target.value)} required /></label>
        </div>
        <div className="form-grid">
          <label>IP family<select name="family" defaultValue="ipv4"><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
          <label>Remote port<input name="remote_port" defaultValue="any" placeholder="any hoặc 1-65535" /></label>
        </div>
        <div className="form-grid">
          <label>Nguồn (CIDR)<input name="source" defaultValue="any" placeholder="10.10.0.0/16 hoặc any" /></label>
          <label>Đích local (CIDR)<input name="destination" defaultValue="any" placeholder="any" /></label>
        </div>
        <div className="resource-help">Agent tự đọc trạng thái thật ngay lúc chạy: Windows chọn Windows Firewall, Ubuntu chọn UFW đang active, Oracle Linux/Red Hat chọn default firewalld zone; nếu máy dùng nftables/iptables Agent chọn đúng filter INPUT theo IP family. Linux common rule giới hạn Inbound để tương thích an toàn với firewalld zone.</div>
      </> : null}
      {(action !== "patch.install" || step === 2) && <label>Lý do / ticket<textarea name="reason" rows={2} minLength={5} maxLength={2000} required placeholder="CHG-1234 · Mô tả mục đích áp dụng hàng loạt" /></label>}
      {error ? <div className="resource-job-state failed"><b>Không thể tạo task</b><span>{error}</span></div> : null}
    </form>
  </ModalShell>;
}

function SystemUnavailable({ message }: { message: string }) {
  return (
    <div className="login-page">
      <div className="login-glow" />
      <section className="system-unavailable">
        <span className="setup-state-icon">!</span>
        <p className="login-eyebrow">HỆ THỐNG TẠM GIÁN ĐOẠN</p>
        <h1>Không thể kiểm tra cấu hình</h1>
        <p>{message}. Hãy kiểm tra dịch vụ vận hành rồi tải lại trang.</p>
        <button
          className="button primary"
          onClick={() => window.location.reload()}
        >
          Thử lại
        </button>
      </section>
    </div>
  );
}

function SetupScreen({
  status,
  onComplete,
}: {
  status: SetupStatus;
  onComplete: (dashboardUrl: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const password = String(form.get("admin_password") ?? "");
    if (password !== String(form.get("admin_password_confirm") ?? "")) {
      setError("Mật khẩu quản trị nhập lại chưa khớp.");
      setBusy(false);
      return;
    }
    const dashboardUrl = String(form.get("dashboard_url") ?? "").replace(
      /\/$/,
      "",
    );
    try {
      const response = await fetch("/api/v1/setup/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          database: {
            host: form.get("db_host"),
            port: Number(form.get("db_port")),
            database: form.get("db_name"),
            username: form.get("db_username"),
            password: form.get("db_password"),
            sslmode: form.get("db_sslmode"),
          },
          admin: {
            username: form.get("admin_username"),
            display_name: form.get("admin_display_name"),
            password,
          },
          dashboard_url: dashboardUrl,
          setup_token: form.get("setup_token") ?? "",
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(data.detail ?? "Không thể hoàn tất thiết lập");
      onComplete(data.dashboardUrl ?? dashboardUrl);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Không thể hoàn tất thiết lập",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="setup-page">
      <div className="setup-orbit" />
      <header className="setup-header">
        <div className="login-brand">
          <span className="brand-mark">O</span>
          <div>
            <b>Operation</b>
            <small>Portal</small>
          </div>
        </div>
        <span className="setup-badge">
          <i /> THIẾT LẬP LẦN ĐẦU
        </span>
      </header>
      <div className="setup-layout">
        <aside className="setup-intro">
          <p className="login-eyebrow">THIẾT LẬP AN TOÀN</p>
          <h1>Khởi tạo trung tâm vận hành</h1>
          <p>
            Kết nối kho dữ liệu, tạo quản trị viên local đầu tiên và xác lập địa
            chỉ chính thức cho Operation Portal.
          </p>
          <ol className="setup-steps">
            <li className="active">
              <span>01</span>
              <div>
                <b>Kho dữ liệu</b>
                <small>Kết nối và kiểm tra quyền lưu trữ</small>
              </div>
            </li>
            <li className="active">
              <span>02</span>
              <div>
                <b>Quản trị viên</b>
                <small>Tài khoản local toàn quyền đầu tiên</small>
              </div>
            </li>
            <li className="active">
              <span>03</span>
              <div>
                <b>Địa chỉ truy cập</b>
                <small>URL chính thức của Operation Portal</small>
              </div>
            </li>
          </ol>
          <div className="setup-note">
            <span>◆</span>
            <p>
              <b>Dữ liệu vận hành được bảo vệ</b>
              <small>
                Tài khoản, máy chủ, tác vụ, cấu hình và nhật ký được lưu bền vững
                và chỉ truy cập theo quyền được cấp.
              </small>
            </p>
          </div>
        </aside>

        <form className="setup-card" onSubmit={submit}>
          <div className="setup-card-head">
            <div>
              <p className="login-eyebrow">BƯỚC KHỞI TẠO</p>
              <h2>Cấu hình hệ thống</h2>
            </div>
            <div
              className={`connection-state ${status.databaseConnected ? "connected" : ""}`}
            >
              <i />
              {status.databaseConnected ? "Đã kết nối" : "Chưa kết nối"}
            </div>
          </div>

          <fieldset>
            <legend>
              <span>01</span>
              <div>
                <b>Kết nối kho dữ liệu</b>
                <small>
                  Kho dữ liệu cần tồn tại và tài khoản phải có quyền khởi tạo.
                </small>
              </div>
            </legend>
            <div className="setup-grid three">
              <label>
                Máy chủ
                <input
                  name="db_host"
                  required
                  placeholder="data.internal"
                  autoComplete="off"
                />
              </label>
              <label>
                Cổng
                <input
                  name="db_port"
                  type="number"
                  min="1"
                  max="65535"
                  placeholder="Nhập cổng"
                  required
                />
              </label>
              <label>
                SSL
                <select name="db_sslmode" defaultValue="prefer">
                  <option value="prefer">Ưu tiên SSL</option>
                  <option value="require">Bắt buộc SSL</option>
                  <option value="verify-ca">Xác minh CA</option>
                  <option value="verify-full">Xác minh đầy đủ</option>
                  <option value="disable">Tắt SSL</option>
                </select>
              </label>
            </div>
            <div className="setup-grid">
              <label>
                Tên kho dữ liệu
                <input
                  name="db_name"
                  required
                  autoComplete="off"
                />
              </label>
              <label>
                Tài khoản kết nối
                <input
                  name="db_username"
                  required
                  autoComplete="username"
                />
              </label>
            </div>
            <label>
              Mật khẩu kết nối
              <input
                name="db_password"
                type="password"
                required
                autoComplete="current-password"
              />
            </label>
          </fieldset>

          <fieldset>
            <legend>
              <span>02</span>
              <div>
                <b>Admin local đầu tiên</b>
                <small>
                  Dùng để đăng nhập khi chưa tích hợp hệ thống định danh doanh
                  nghiệp.
                </small>
              </div>
            </legend>
            <div className="setup-grid">
              <label>
                Tên đăng nhập
                <input
                  name="admin_username"
                  defaultValue="admin"
                  minLength={3}
                  pattern="[A-Za-z0-9_.@-]+"
                  required
                  autoComplete="username"
                />
              </label>
              <label>
                Tên hiển thị
                <input
                  name="admin_display_name"
                  defaultValue="Platform Administrator"
                  required
                />
              </label>
            </div>
            <div className="setup-grid">
              <label>
                Mật khẩu
                <input
                  name="admin_password"
                  type="password"
                  minLength={14}
                  required
                  autoComplete="new-password"
                  placeholder="Tối thiểu 14 ký tự"
                />
              </label>
              <label>
                Nhập lại mật khẩu
                <input
                  name="admin_password_confirm"
                  type="password"
                  minLength={14}
                  required
                  autoComplete="new-password"
                />
              </label>
            </div>
          </fieldset>

          <fieldset>
            <legend>
              <span>03</span>
              <div>
                <b>Địa chỉ dashboard</b>
                <small>URL HTTPS chính thức mà người dùng có thể truy cập.</small>
              </div>
            </legend>
            <label>
              Dashboard URL
              <input
                name="dashboard_url"
                type="url"
                defaultValue={
                  typeof window !== "undefined"
                    ? window.location.origin
                    : "https://ops.example.com"
                }
                required
                placeholder="https://ops.example.com"
              />
            </label>
            {status.setupTokenRequired && (
              <label>
                Mã thiết lập
                <input
                  name="setup_token"
                  type="password"
                  required
                  autoComplete="one-time-code"
                />
                <small className="field-hint">
                  Giá trị SETUP_TOKEN do người triển khai cung cấp.
                </small>
              </label>
            )}
          </fieldset>

          {error && (
            <div className="setup-error">
              <span>!</span>
              <p>
                <b>Chưa thể hoàn tất thiết lập</b>
                <small>{error}</small>
              </p>
            </div>
          )}
          <div className="setup-actions">
            <p>
              <span>◆</span> Thông tin bí mật không được hiển thị lại sau khi lưu.
            </p>
            <button className="button primary" disabled={busy}>
              {busy
                ? "Đang kiểm tra và khởi tạo…"
                : "Kiểm tra kết nối & hoàn tất"}
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}

function LoginScreen({ onLogin }: { onLogin: () => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"local" | "domain">("local");
  const [mfaCode, setMfaCode] = useState("");
  const mfaCodeRef = useRef<HTMLInputElement>(null);
  const [mfa, setMfa] = useState<{
    challenge_token: string;
    setup_required: boolean;
    qr_svg?: string;
    provisioning_uri?: string;
  } | null>(null);
  useEffect(() => {
    if (!mfa) return;
    const frame = window.requestAnimationFrame(() => mfaCodeRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [mfa]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
          source,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không thể đăng nhập");
      setMfaCode("");
      setMfa(data);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Không thể đăng nhập",
      );
    } finally {
      setBusy(false);
    }
  }
  async function verifyMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!mfa) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/v1/auth/mfa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Tram-Auth-Mode": "cookie" },
        body: JSON.stringify({
          challenge_token: mfa.challenge_token,
          code: mfaCode,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        setMfaCode("");
        throw new Error(data.detail ?? "Mã MFA không hợp lệ");
      }
      onLogin();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Không thể xác thực MFA",
      );
    } finally {
      setBusy(false);
    }
  }
  if (mfa)
    return (
      <div className="login-page">
        <div className="login-glow" />
        <form className="login-card mfa-card" onSubmit={verifyMfa} autoComplete="off">
          <div className="login-brand">
            <span className="brand-mark">O</span>
            <div>
              <b>Operation</b>
              <small>Portal · MFA</small>
            </div>
          </div>
          <p className="login-eyebrow">MULTI-FACTOR AUTHENTICATION</p>
          <h1>
            {mfa.setup_required ? "Thiết lập MFA lần đầu" : "Nhập mã xác thực"}
          </h1>
          <p className="login-copy">
            {mfa.setup_required
              ? "Quét QR bằng Microsoft Authenticator, Google Authenticator hoặc ứng dụng TOTP tương thích."
              : "Nhập mã 6 số hiện tại từ ứng dụng xác thực."}
          </p>
          {mfa.setup_required && mfa.qr_svg && (
            // QR is an API-provided data URI; image optimization cannot process it.
            // eslint-disable-next-line @next/next/no-img-element
            <img
              className="mfa-qr"
              src={mfa.qr_svg}
              alt="QR thiết lập MFA"
            />
          )}
          <input className="login-autofill-sink" name="username" autoComplete="username" tabIndex={-1} aria-hidden="true" />
          <label>
            Mã MFA 6 số
            <input
              name="totp_code"
              ref={mfaCodeRef}
              inputMode="numeric"
              autoComplete="one-time-code"
              value={mfaCode}
              onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
              pattern="[0-9]{6}"
              maxLength={6}
              required
              placeholder="000000"
            />
          </label>
          {error && <div className="login-error">{error}</div>}
          <button className="button primary" disabled={busy}>
            {busy ? "Đang kiểm tra…" : "Xác nhận và đăng nhập"}
          </button>
          <button
            type="button"
            className="login-back"
            onClick={() => {
              setMfa(null);
              setMfaCode("");
              setError("");
            }}
          >
            ← Quay lại đăng nhập
          </button>
        </form>
      </div>
    );
  return (
    <div className="login-page">
      <div className="login-glow" />
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <span className="brand-mark">O</span>
          <div>
            <b>Operation</b>
            <small>Portal</small>
          </div>
        </div>
        <p className="login-eyebrow">TRUY CẬP AN TOÀN</p>
        <h1>Đăng nhập hệ thống</h1>
        <div className="login-tabs">
          <button
            type="button"
            className={source === "local" ? "active" : ""}
            onClick={() => setSource("local")}
          >
            Local
          </button>
          <button
            type="button"
            className={source === "domain" ? "active" : ""}
            onClick={() => setSource("domain")}
          >
            Domain Login
          </button>
        </div>
        <p className="login-copy">
          {source === "local"
            ? "Đăng nhập bằng tài khoản Local của Operation Portal."
            : "Xác thực bằng tài khoản LDAP/Active Directory của doanh nghiệp."}
        </p>
        <label>
          Tên đăng nhập
          <input
            name="username"
            autoComplete="username"
            required
            placeholder={source === "local" ? "admin" : "nguyen.anh"}
          />
        </label>
        <label>
          Mật khẩu
          <input
            type="password"
            name="password"
            autoComplete="current-password"
            required
            placeholder="••••••••••••••"
          />
        </label>
        {error && <div className="login-error">{error}</div>}
        <button className="button primary" disabled={busy}>
          {busy ? "Đang xác thực…" : "Tiếp tục với MFA"}
        </button>
        <div className="login-security">
          <span>◆</span>
          <p>
            <b>MFA bắt buộc · RBAC · Audit bất biến</b>
            <small>
              Mỗi người dùng phải đăng ký TOTP trong lần đăng nhập đầu tiên.
            </small>
          </p>
        </div>
      </form>
    </div>
  );
}

type ServerTab =
  | "overview"
  | "storage"
  | "services"
  | "accounts"
  | "firewall"
  | "processes"
  | "updates"
  | "files"
  | "logs";

const serverTabs: Array<{ id: ServerTab; label: string; icon: string }> = [
  { id: "overview", label: "Tổng quan", icon: "⌂" },
  { id: "storage", label: "Disk", icon: "◫" },
  { id: "services", label: "Services", icon: "◉" },
  { id: "accounts", label: "Tài khoản", icon: "◎" },
  { id: "firewall", label: "Firewall", icon: "◇" },
  { id: "processes", label: "Tiến trình", icon: "▤" },
  { id: "updates", label: "Cập nhật", icon: "↥" },
  { id: "files", label: "Truyền file", icon: "↳" },
  { id: "logs", label: "Nhật ký", icon: "≡" },
];

const readActionByTab: Partial<Record<ServerTab, string>> = {
  storage: "storage.list",
  services: "service.list",
  accounts: "user.list",
  firewall: "firewall.list",
  processes: "process.list",
  updates: "patch.scan",
  logs: "logs.read",
};

function ServerDrawer({
  server,
  close,
  openSession,
  notify,
  token,
  canConfigureLogs,
  permissions,
  readOnly,
}: {
  server: Server;
  close: () => void;
  openSession: () => void;
  notify: (message: string) => void;
  token: string;
  canConfigureLogs: boolean;
  permissions: string[];
  readOnly: boolean;
}) {
  type Fact = {
    name?: string;
    Name?: string;
    members?: string[];
    Members?: string[];
    path?: string;
    Path?: string;
    DriveLetter?: string;
    DisplayName?: string;
    Status?: string;
    StartType?: string;
    state?: string;
    Enabled?: boolean;
    uid?: number;
    home?: string;
    shell?: string;
    Size?: number;
    SizeRemaining?: number;
    FileSystem?: string;
    size?: number;
    fstype?: string;
    mountpoints?: string[];
  };
  type Detail = {
    inventory?: {
      extra?: {
        Users?: Fact[];
        Groups?: Fact[];
        Storage?: Fact[];
        Services?: Fact[];
      };
    };
  };
  type ServerJob = {
    id: string;
    action: string;
    status: string;
    reason: string;
    output?: string;
    exitCode?: number | null;
    createdAt: string;
    finishedAt?: string | null;
  };
  const [detail, setDetail] = useState<Detail | null>(null);
  const [activeTab, setActiveTab] = useState<ServerTab>("overview");
  const [busy, setBusy] = useState(false);
  const [firewallModal, setFirewallModal] = useState<"add" | "delete" | "reorder" | null>(null);
  const [selectedFirewallRules, setSelectedFirewallRules] = useState<string[]>([]);
  const [firewallSearch, setFirewallSearch] = useState("");
  const [firewallActionFilter, setFirewallActionFilter] = useState("all");
  const [firewallDirectionFilter, setFirewallDirectionFilter] = useState("all");
  const [firewallStateFilter, setFirewallStateFilter] = useState("all");
  const [firewallBackendFilter, setFirewallBackendFilter] = useState("all");
  const [firewallConfirmation, setFirewallConfirmation] = useState("");
  const [draggedFirewallRule, setDraggedFirewallRule] = useState<string | null>(null);
  const [firewallReorder, setFirewallReorder] = useState<{ rule: FirewallRule; before: FirewallRule | null } | null>(null);
  const [fileBusy, setFileBusy] = useState(false);
  const [transfers, setTransfers] = useState<
    Array<{
      id: string;
      filename: string;
      sizeBytes: number;
      sha256: string;
      status: string;
    }>
  >([]);
  const [jobs, setJobs] = useState<ServerJob[]>([]);
  const [configuredLogSources, setConfiguredLogSources] = useState<string[]>(server.osFamily === "windows" ? ["System"] : ["journal"]);
  const loadTransfers = useCallback(
    () =>
      fetch(`/api/v1/servers/${server.id}/files`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((response) => (response.ok ? response.json() : Promise.reject()))
        .then((data) => setTransfers(Array.isArray(data.items) ? data.items : []))
        .catch(() => setTransfers([])),
    [server.id, token],
  );
  const loadDetail = useCallback(
    () =>
      fetch(`/api/v1/servers/${server.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((response) => (response.ok ? response.json() : Promise.reject()))
        .then(setDetail)
        .catch(() => setDetail(null)),
    [server.id, token],
  );
  const loadJobs = useCallback(
    () =>
      fetch(`/api/v1/servers/${server.id}/jobs`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((response) => (response.ok ? response.json() : Promise.reject()))
        .then((data) => setJobs(Array.isArray(data.items) ? data.items : []))
        .catch(() => setJobs([])),
    [server.id, token],
  );
  const loadLogSources = useCallback(
    () =>
      fetch(`/api/v1/servers/${server.id}/log-sources`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((response) => (response.ok ? response.json() : Promise.reject()))
        .then((data) => setConfiguredLogSources(Array.isArray(data.sources) ? data.sources : server.osFamily === "windows" ? ["System"] : ["journal"]))
        .catch(() => setConfiguredLogSources(server.osFamily === "windows" ? ["System"] : ["journal"])),
    [server.id, server.osFamily, token],
  );
  useEffect(() => {
    void loadDetail();
    void loadTransfers();
    void loadJobs();
    void loadLogSources();
    const timer = window.setInterval(() => void loadJobs(), 5_000);
    return () => window.clearInterval(timer);
  }, [loadDetail, loadTransfers, loadJobs, loadLogSources]);
  const facts = detail?.inventory?.extra;
  const groups = (facts?.Groups ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  const users = (facts?.Users ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  const storage = facts?.Storage ?? [];
  const currentReadAction = readActionByTab[activeTab];
  const latestReadJob = currentReadAction
    ? jobs.find((job) => job.action === currentReadAction)
    : undefined;
  const latestSuccessfulReadJob = currentReadAction
    ? jobs.find((job) => job.action === currentReadAction && job.status === "succeeded")
    : undefined;
  const successfulUpdateScanJobs = jobs.filter((job) => job.action === "patch.scan" && job.status === "succeeded");
  const latestUserJob = jobs.find((job) => job.action === "user.list");
  const latestSuccessfulUserJob = jobs.find((job) => job.action === "user.list" && job.status === "succeeded");
  const latestGroupJob = jobs.find((job) => job.action === "group.list");
  const latestSuccessfulGroupJob = jobs.find((job) => job.action === "group.list" && job.status === "succeeded");
  const latestSuccessfulLogSourcesJob = jobs.find((job) => job.action === "logs.sources" && job.status === "succeeded");
  const latestFirewallJob = jobs.find((job) => job.action === "firewall.list");
  const latestSuccessfulFirewallJob = jobs.find((job) => job.action === "firewall.list" && job.status === "succeeded");
  const latestFirewallMutation = jobs.find((job) =>
    ["firewall.rule.add", "firewall.rule.remove", "firewall.rule.reorder"].includes(job.action) && job.status !== "cancelled",
  );
  const autoRefreshForLatestMutation = latestFirewallMutation
    ? jobs.find((job) => job.action === "firewall.list" && job.reason.includes(latestFirewallMutation.id.slice(0, 8)))
    : undefined;
  const mutationIsActive = Boolean(
    latestFirewallMutation && ["queued", "dispatched"].includes(latestFirewallMutation.status),
  );
  const mutationNeedsRefresh = Boolean(
    latestFirewallMutation &&
    (mutationIsActive || (autoRefreshForLatestMutation
      ? autoRefreshForLatestMutation.status !== "succeeded"
      : !latestSuccessfulFirewallJob || new Date(latestFirewallMutation.createdAt) > new Date(latestSuccessfulFirewallJob.createdAt))),
  );
  const firewallScan = parseFirewallOutput(latestSuccessfulFirewallJob?.output);
  const firewallRules = firewallScan.rules;
  const filteredFirewallRules = firewallRules.filter((rule) => {
    const query = firewallSearch.trim().toLocaleLowerCase("vi");
    const matchesSearch = !query || [
      rule.name, rule.id, rule.backend, rule.direction, rule.action, rule.protocol,
      rule.localPort, rule.remotePort, rule.source, rule.destination, rule.profile,
    ].some((value) => String(value ?? "").toLocaleLowerCase("vi").includes(query));
    return matchesSearch &&
      (firewallActionFilter === "all" || String(rule.action ?? "").toLowerCase() === firewallActionFilter) &&
      (firewallDirectionFilter === "all" || String(rule.direction ?? "").toLowerCase() === firewallDirectionFilter) &&
      (firewallStateFilter === "all" || (firewallStateFilter === "enabled" ? rule.enabled : !rule.enabled)) &&
      (firewallBackendFilter === "all" || rule.backend === firewallBackendFilter);
  });
  const selectedRules = firewallRules.filter((rule) =>
    selectedFirewallRules.includes(firewallRuleKey(rule)),
  );
  const removableRules = filteredFirewallRules.filter((rule) => rule.removable !== false);
  async function queueJob(
    nextAction: string,
    parameters: Record<string, unknown>,
    reason: string,
    announce = true,
  ) {
    if (readOnly) throw new Error("Vai trò Viewer chỉ được xem dữ liệu đã thu thập, không tạo tác vụ.");
    if (/^(user\.|group\.)/.test(nextAction) && !["user.list", "group.list"].includes(nextAction) && !permissions.includes("accounts.manage")) throw new Error("Không có quyền cấu hình tài khoản.");
    const response = await fetch("/api/v1/jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        server_id: server.id,
        action: nextAction,
        parameters,
        reason,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Không thể tạo tác vụ");
    if (announce) notify(data.status === "pending_approval" ? "Đã gửi yêu cầu xóa; chờ một Administrator duyệt, chưa gửi tới Agent." : `Đã gửi tác vụ ${nextAction} tới Agent · ${data.status}.`);
    await loadJobs();
    return data as { id: string; status: string; risk: string };
  }
  async function refreshCurrentTab(parameters: Record<string, unknown> = {}) {
    if (readOnly) { await loadJobs(); return; }
    if (!currentReadAction && activeTab !== "accounts") return;
    setBusy(true);
    try {
      if (activeTab === "accounts") {
        await queueJob("user.list", {}, `Đọc Users từ ${server.name}`);
        await queueJob("group.list", {}, `Đọc Groups từ ${server.name}`);
      } else if (activeTab === "logs") {
        await queueJob("logs.sources", {}, `Quét nguồn log từ ${server.name}`);
        await queueJob("logs.read", {}, `Đọc 500 dòng log từ ${server.name}`);
      } else if (currentReadAction) {
        await queueJob(currentReadAction, parameters, `Đọc dữ liệu ${activeTab} từ ${server.name}`, currentReadAction !== "process.list");
      }
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể yêu cầu dữ liệu mới");
    } finally {
      setBusy(false);
    }
  }
  function selectTab(tab: ServerTab) {
    setActiveTab(tab);
    if (readOnly) return;
    if (tab === "firewall" && (!latestFirewallJob || latestFirewallJob.status === "failed"))
      void queueJob("firewall.list", {}, `Quét firewall rules trên ${server.name}`).catch((reason) =>
        notify(reason instanceof Error ? reason.message : "Không thể quét firewall"),
      );
    if (tab === "accounts") {
      if (!jobs.some((job) => job.action === "user.list" && job.status !== "failed")) void queueJob("user.list", {}, `Đọc Users từ ${server.name}`).catch((reason) => notify(reason instanceof Error ? reason.message : "Không thể đọc Users"));
      if (!jobs.some((job) => job.action === "group.list" && job.status !== "failed")) void queueJob("group.list", {}, `Đọc Groups từ ${server.name}`).catch((reason) => notify(reason instanceof Error ? reason.message : "Không thể đọc Groups"));
      return;
    }
    if (tab === "logs") {
      if (!jobs.some((job) => job.action === "logs.sources" && job.status !== "failed")) void queueJob("logs.sources", {}, `Quét nguồn log từ ${server.name}`).catch((reason) => notify(reason instanceof Error ? reason.message : "Không thể quét nguồn log"));
      if (!jobs.some((job) => job.action === "logs.read" && job.status !== "failed")) void queueJob("logs.read", {}, `Đọc 500 dòng log từ ${server.name}`).catch((reason) => notify(reason instanceof Error ? reason.message : "Không thể đọc log"));
      return;
    }
    const readAction = readActionByTab[tab];
    if (readAction && tab !== "firewall" && !jobs.some((job) => job.action === readAction && job.status !== "failed"))
      void queueJob(readAction, {}, `Đọc dữ liệu ${tab} từ ${server.name}`).catch((reason) => notify(reason instanceof Error ? reason.message : "Không thể đọc dữ liệu"));
  }
  async function runResourceAction(nextAction: string, parameters: Record<string, unknown>, reason: string) {
    setBusy(true);
    try {
      await queueJob(nextAction, parameters, reason);
      return true;
    } catch (error) {
      notify(error instanceof Error ? error.message : "Không thể gửi tác vụ");
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function saveLogSources(sources: string[]) {
    setBusy(true);
    try {
      const response = await fetch(`/api/v1/servers/${server.id}/log-sources`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ sources }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không thể lưu nguồn log");
      setConfiguredLogSources(data.sources);
      await queueJob("logs.read", {}, `Đọc 500 dòng log sau khi đổi cấu hình trên ${server.name}`);
      return true;
    } catch (error) {
      notify(error instanceof Error ? error.message : "Không thể lưu nguồn log");
      return false;
    } finally {
      setBusy(false);
    }
  }
  function closeFirewallModal() {
    setFirewallModal(null);
    setFirewallConfirmation("");
    setFirewallReorder(null);
  }
  function toggleFirewallRule(rule: FirewallRule) {
    if (rule.removable === false) return;
    const key = firewallRuleKey(rule);
    setSelectedFirewallRules((current) => {
      if (current.includes(key)) return current.filter((item) => item !== key);
      if (current.length >= 200) {
        notify("Mỗi tác vụ được chọn tối đa 200 firewall rule.");
        return current;
      }
      return [...current, key];
    });
  }
  function toggleAllFirewallRules() {
    const keys = removableRules.slice(0, 200).map(firewallRuleKey);
    setSelectedFirewallRules((current) =>
      keys.length > 0 && keys.every((key) => current.includes(key)) ? [] : keys,
    );
  }
  async function submitFirewallRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const parameters: Record<string, unknown> = {};
    for (const [key, value] of form.entries())
      if (key !== "reason" && value !== "") parameters[key] = value;
    if (parameters.local_port && String(parameters.local_port).toLowerCase() !== "any")
      parameters.local_port = Number(parameters.local_port);
    if (parameters.remote_port && String(parameters.remote_port).toLowerCase() !== "any")
      parameters.remote_port = Number(parameters.remote_port);
    try {
      await queueJob(
        "firewall.rule.add",
        parameters,
        String(form.get("reason") ?? "Thêm firewall rule từ máy chủ đã chọn"),
      );
      closeFirewallModal();
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể tạo firewall rule");
    } finally {
      setBusy(false);
    }
  }
  async function deleteFirewallRules() {
    if (firewallConfirmation !== "CONFIRM" || selectedRules.length === 0) return;
    setBusy(true);
    try {
      await queueJob(
        "firewall.rule.remove",
        {
          rules: selectedRules.map((rule) => ({
            id: rule.id,
            backend: rule.backend,
            raw: rule.raw,
            spec: rule.spec,
          })),
        },
        `Xóa ${selectedRules.length} firewall rule đã xác nhận trên ${server.name}`,
      );
      setSelectedFirewallRules([]);
      closeFirewallModal();
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể xóa firewall rule");
    } finally {
      setBusy(false);
    }
  }
  function dropFirewallRule(target: FirewallRule, event: DragEvent<HTMLTableRowElement>) {
    event.preventDefault();
    const source = firewallRules.find((rule) => firewallRuleKey(rule) === draggedFirewallRule);
    setDraggedFirewallRule(null);
    if (!source || source.reorderable !== true || target.reorderable !== true || source.orderGroup !== target.orderGroup || source.id === target.id) return;
    const group = firewallRules.filter((rule) => rule.orderGroup === source.orderGroup);
    const remaining = group.filter((rule) => rule.id !== source.id);
    const targetIndex = remaining.findIndex((rule) => rule.id === target.id);
    if (targetIndex < 0) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const afterTarget = event.clientY >= bounds.top + bounds.height / 2;
    const desired = [...remaining];
    desired.splice(targetIndex + (afterTarget ? 1 : 0), 0, source);
    const sourcePosition = desired.findIndex((rule) => rule.id === source.id);
    const before = desired[sourcePosition + 1] ?? null;
    const currentPosition = group.findIndex((rule) => rule.id === source.id);
    const currentBefore = group[currentPosition + 1] ?? null;
    if ((before?.id ?? null) === (currentBefore?.id ?? null)) return;
    setFirewallReorder({ rule: source, before });
    setFirewallModal("reorder");
  }
  async function submitFirewallReorder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!firewallReorder) return;
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const compactRule = (rule: FirewallRule) => ({ id: rule.id, backend: rule.backend, raw: rule.raw, spec: rule.spec });
    try {
      await queueJob(
        "firewall.rule.reorder",
        { rule: compactRule(firewallReorder.rule), before: firewallReorder.before ? compactRule(firewallReorder.before) : null },
        String(form.get("reason") ?? `Sắp xếp firewall rule trên ${server.name}`),
      );
      closeFirewallModal();
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể sắp xếp firewall rule");
    } finally {
      setBusy(false);
    }
  }
  async function uploadFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!permissions.includes("files.manage")) return notify("Bạn không có quyền gửi file.");
    setFileBusy(true);
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    try {
      const selectedFile = form.get("file");
      if (selectedFile instanceof File && selectedFile.size > 1024 * 1024 * 1024)
        throw new Error("File vượt quá giới hạn 1 GiB");
      const response = await fetch(`/api/v1/servers/${server.id}/files`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(data.detail ?? "Không thể tải file vào vùng cách ly");
      notify("File sạch đã được xếp hàng để Agent nhận và chuyển vào inbox cách ly.");
      formElement.reset();
      await loadTransfers();
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể tải file");
    } finally {
      setFileBusy(false);
    }
  }
  return (
    <>
      <section className="server-workspace">
        <nav className="server-breadcrumb" aria-label="Đường dẫn máy chủ">
          <a href={sectionRoute(server.osFamily)} onClick={(event) => { event.preventDefault(); close(); }}>
            {server.osFamily === "windows" ? "Máy chủ Windows" : "Máy chủ Linux"}
          </a>
          <span>/</span>
          <strong>{server.name}</strong>
        </nav>
        <div className="drawer-top">
          <button onClick={close} aria-label="Quay lại danh sách">←</button>
          <span className={`os-avatar large ${server.osFamily}`}>
            {server.osFamily === "windows" ? "W" : ">_"}
          </span>
          <div>
            <span className={`status ${server.health}`}>
              <i />
              {healthLabel[server.health]}
            </span>
            <h2>{server.name}</h2>
            <p>
              {server.os} {server.version}
            </p>
          </div>
        </div>
        <div className="drawer-actions">
          <button className="connect" onClick={openSession} disabled={!permissions.includes("sessions.launch") || !server.tunnelOnline}>
            <span>↗</span>
            <b>{server.osFamily === "windows" ? "Remote Desktop" : "Mở SSH"}</b>
            <small>
              {server.tunnelOnline ? "Kênh truy cập an toàn sẵn sàng" : "Máy chủ đang mất kết nối"}
            </small>
          </button>
          <button
            disabled={readOnly}
            onClick={() =>
              queueJob(
                "inventory.collect",
                {},
                "Làm mới dữ liệu máy chủ",
              ).catch((reason) => notify(reason.message))
            }
          >
            <span>↻</span>
            <b>Làm mới</b>
            <small>Đồng bộ agent</small>
          </button>
        </div>
        <nav className="server-tabs" aria-label="Chức năng vận hành máy chủ">
          {serverTabs.map((tab) => (
            <button
              key={tab.id}
              className={activeTab === tab.id ? "active" : ""}
              onClick={() => selectTab(tab.id)}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>
        {readOnly && <p className="resource-help">Chế độ chỉ xem: dữ liệu đã thu thập. Không thể mở phiên, quét Agent hoặc thay đổi cấu hình.</p>}
        <div className="drawer-body">
          {activeTab === "overview" && (
            <>
          <h3>Tài nguyên</h3>
          <div className="resource-grid">
            <div>
              <span>
                <b>CPU</b>
                <strong>{server.cpu}%</strong>
              </span>
              <MiniBar value={server.cpu} />
            </div>
            <div>
              <span>
                <b>Bộ nhớ</b>
                <strong>{server.memory}%</strong>
              </span>
              <MiniBar value={server.memory} />
            </div>
            <div>
              <span>
                <b>Ổ đĩa</b>
                <strong>{server.disk}%</strong>
              </span>
              <MiniBar value={server.disk} dangerAt={90} />
            </div>
          </div>
          <h3>Thông tin lấy từ máy chủ</h3>
          <div className="fact-grid">
            <div>
              <b>{users.length}</b>
              <small>tài khoản local</small>
            </div>
            <div>
              <b>{groups.length}</b>
              <small>nhóm local</small>
            </div>
            <div>
              <b>{storage.length}</b>
              <small>ổ/volume</small>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Địa chỉ quản trị</dt>
              <dd>{server.address}</dd>
            </div>
            <div>
              <dt>Nhóm hiện có</dt>
              <dd>{groups.slice(0, 8).join(", ") || "Đang đồng bộ…"}</dd>
            </div>
            <div>
              <dt>Agent</dt>
              <dd>
                v{server.agentVersion} · {server.tunnelOnline ? "kết nối an toàn" : "mất kết nối"}
              </dd>
            </div>
          </dl>
            </>
          )}

          {activeTab !== "overview" && activeTab !== "files" && (
            <>
              {activeTab === "firewall" && <div className="server-tab-toolbar">
                <div>
                  <h2>{serverTabs.find((tab) => tab.id === activeTab)?.label}</h2>
                  <p>Thông tin được cập nhật trực tiếp từ máy chủ đang quản trị.</p>
                </div>
                <div className="firewall-toolbar-actions">
                  <button className="button ghost" onClick={() => void refreshCurrentTab()} disabled={busy}>
                    {busy ? "Đang quét…" : "↻ Quét lại"}
                  </button>
                  {permissions.includes("firewall.manage") && <><button className="firewall-icon-button add" type="button" aria-label="Thêm firewall rule" title="Thêm firewall rule" onClick={() => setFirewallModal("add")}>+</button><button className="firewall-icon-button remove" type="button" aria-label="Xóa firewall rule đã chọn" title="Xóa firewall rule đã chọn" disabled={selectedRules.length === 0} onClick={() => { setFirewallConfirmation(""); setFirewallModal("delete"); }}>−</button></>}
                </div>
              </div>}

              {activeTab === "storage" && (
                <StorageResourceTab output={latestSuccessfulReadJob?.output} job={latestReadJob} serverName={server.name} osFamily={server.osFamily} busy={busy || readOnly} refresh={() => void refreshCurrentTab()} queue={runResourceAction} />
              )}

              {activeTab === "services" && (
                <ServicesResourceTab output={latestSuccessfulReadJob?.output} job={latestReadJob} serverName={server.name} busy={busy || readOnly} refresh={() => void refreshCurrentTab()} queue={runResourceAction} />
              )}

              {activeTab === "accounts" && (
                <AccountsResourceTab userOutput={latestSuccessfulUserJob?.output} groupOutput={latestSuccessfulGroupJob?.output} job={latestUserJob?.status === "failed" ? latestUserJob : latestGroupJob} serverName={server.name} osFamily={server.osFamily} busy={busy || !permissions.includes("accounts.manage")} refresh={() => void refreshCurrentTab()} queue={runResourceAction} />
              )}

              {activeTab === "firewall" && (
                <section className="firewall-rule-panel">
                  <div className="firewall-rule-summary">
                    <span><b>{filteredFirewallRules.length}</b> / {firewallRules.length} rule · backend <strong>{firewallScan.backend || "chưa xác định"}</strong></span>
                    <span>{selectedRules.length} rule đang chọn</span>
                  </div>
                  <div className="firewall-filter-bar" aria-label="Tìm kiếm và lọc firewall rule">
                    <label className="firewall-search-field">
                      <span>⌕</span>
                      <input
                        type="search"
                        value={firewallSearch}
                        onChange={(event) => setFirewallSearch(event.target.value)}
                        placeholder="Tìm tên, ID, IP, cổng, profile / zone…"
                        aria-label="Tìm firewall rule"
                      />
                    </label>
                    <select value={firewallActionFilter} onChange={(event) => setFirewallActionFilter(event.target.value)} aria-label="Lọc theo action">
                      <option value="all">Mọi action</option>
                      <option value="allow">Allow</option>
                      <option value="accept">Accept</option>
                      <option value="block">Block</option>
                      <option value="deny">Deny</option>
                      <option value="drop">Drop</option>
                      <option value="reject">Reject</option>
                    </select>
                    <select value={firewallDirectionFilter} onChange={(event) => setFirewallDirectionFilter(event.target.value)} aria-label="Lọc theo hướng">
                      <option value="all">Mọi hướng</option>
                      <option value="inbound">Inbound</option>
                      <option value="outbound">Outbound</option>
                      <option value="in">In</option>
                      <option value="out">Out</option>
                      <option value="forward">Forward</option>
                    </select>
                    <select value={firewallStateFilter} onChange={(event) => setFirewallStateFilter(event.target.value)} aria-label="Lọc theo trạng thái">
                      <option value="all">Mọi trạng thái</option>
                      <option value="enabled">Enabled</option>
                      <option value="disabled">Disabled</option>
                    </select>
                    <select value={firewallBackendFilter} onChange={(event) => setFirewallBackendFilter(event.target.value)} aria-label="Lọc theo backend">
                      <option value="all">Mọi backend</option>
                      {[...new Set(firewallRules.map((rule) => rule.backend))].map((backend) => <option key={backend} value={backend}>{backend}</option>)}
                    </select>
                    {(firewallSearch || firewallActionFilter !== "all" || firewallDirectionFilter !== "all" || firewallStateFilter !== "all" || firewallBackendFilter !== "all") && (
                      <button type="button" className="button ghost firewall-clear-filter" onClick={() => { setFirewallSearch(""); setFirewallActionFilter("all"); setFirewallDirectionFilter("all"); setFirewallStateFilter("all"); setFirewallBackendFilter("all"); }}>Xóa lọc</button>
                    )}
                  </div>
                  {mutationNeedsRefresh && latestFirewallMutation && (
                    <div className={`firewall-mutation-status ${latestFirewallMutation.status}`}>
                      <b>{latestFirewallMutation.action === "firewall.rule.add" ? "Thêm rule" : latestFirewallMutation.action === "firewall.rule.remove" ? "Xóa rule" : "Đổi thứ tự rule"}</b>
                      <span>{latestFirewallMutation.status === "queued"
                          ? "Đang chờ Agent nhận tác vụ"
                          : latestFirewallMutation.status === "dispatched"
                            ? "Agent đang áp dụng thay đổi"
                            : latestFirewallMutation.status === "succeeded"
                              ? "Đã áp dụng · hệ thống đang tự quét lại danh sách"
                              : "Thay đổi thất bại · chi tiết từ Agent ở bên dưới"}</span>
                      {latestFirewallMutation.status === "failed" && (
                        <pre>{latestFirewallMutation.output || "Agent không trả về nội dung lỗi."}</pre>
                      )}
                    </div>
                  )}
                  <div className="firewall-table-scroll">
                    <table className="firewall-table">
                      <thead>
                        <tr>
                          <th className="firewall-drag-cell" aria-label="Thứ tự rule">↕</th>
                          <th className="firewall-check-cell">
                            <input
                              type="checkbox"
                              aria-label="Chọn tất cả firewall rule có thể xóa"
                              checked={removableRules.length > 0 && removableRules.slice(0, 200).every((rule) => selectedFirewallRules.includes(firewallRuleKey(rule)))}
                              onChange={toggleAllFirewallRules}
                            />
                          </th>
                          <th>Rule</th><th>Hướng</th><th>Action</th><th>Protocol / cổng</th><th>Nguồn → Đích</th><th>Profile / Zone</th><th>Trạng thái</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFirewallRules.map((rule) => {
                          const key = firewallRuleKey(rule);
                          return (
                            <tr
                              key={key}
                              className={`${selectedFirewallRules.includes(key) ? "selected" : ""} ${draggedFirewallRule === key ? "dragging" : ""}`.trim()}
                              draggable={rule.reorderable === true}
                              onDragStart={(event) => {
                                if (rule.reorderable !== true) return;
                                event.dataTransfer.effectAllowed = "move";
                                event.dataTransfer.setData("text/plain", key);
                                setDraggedFirewallRule(key);
                              }}
                              onDragEnd={() => setDraggedFirewallRule(null)}
                              onDragOver={(event) => {
                                const source = firewallRules.find((item) => firewallRuleKey(item) === draggedFirewallRule);
                                if (source && source.orderGroup === rule.orderGroup && source.id !== rule.id && rule.reorderable === true) {
                                  event.preventDefault();
                                  event.dataTransfer.dropEffect = "move";
                                }
                              }}
                              onDrop={(event) => dropFirewallRule(rule, event)}
                            >
                              <td className="firewall-drag-cell"><span className={rule.reorderable ? "firewall-drag-handle" : "firewall-drag-disabled"} title={rule.reorderable ? "Kéo lên hoặc xuống trong cùng chain / IP family" : "Backend hoặc rule này không hỗ trợ sắp xếp an toàn"}>⠿</span></td>
                              <td className="firewall-check-cell">
                                <input type="checkbox" checked={selectedFirewallRules.includes(key)} disabled={rule.removable === false} aria-label={`Chọn ${rule.name}`} title={rule.removable === false ? (rule.managedBy === "docker" ? "Rule hạ tầng do Docker quản lý; chỉ hiển thị để tránh làm hỏng mạng container" : "Rule do Group Policy quản lý, không thể xóa tại máy local") : ""} onChange={() => toggleFirewallRule(rule)} />
                              </td>
                              <td><b>{rule.name}</b><small>{rule.backend} · {rule.id}</small></td>
                              <td>{rule.direction || "—"}</td>
                              <td><span className={`firewall-action ${rule.action}`}>{rule.action || "—"}</span></td>
                              <td>{rule.protocol || "any"} · {rule.localPort || "any"}{rule.remotePort && rule.remotePort !== "any" ? ` / remote ${rule.remotePort}` : ""}</td>
                              <td><span className="firewall-address">{rule.source || "any"} → {rule.destination || "any"}</span></td>
                              <td>{rule.profile || "—"}</td>
                              <td><span className={rule.enabled ? "firewall-enabled" : "firewall-disabled"}>{rule.enabled ? "Enabled" : "Disabled"}</span></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {!latestReadJob && <div className="empty-state">Chưa có dữ liệu; nhấn “Quét lại”.</div>}
                    {latestReadJob && ["queued", "dispatched"].includes(latestReadJob.status) && <div className="empty-state">Agent đang tải lại danh sách firewall: {latestReadJob.status}</div>}
                    {latestReadJob?.status === "failed" && <div className="firewall-scan-error"><b>Không thể quét firewall trên agent {server.agentVersion || "chưa rõ phiên bản"}</b><small>Kết quả lúc {new Date(latestReadJob.createdAt).toLocaleString("vi-VN")}. Mở lại tab hoặc bấm “Quét lại” để tạo lần quét mới.</small><pre>{latestReadJob.output || "Agent không trả về nội dung lỗi. Hãy nâng cấp agent và quét lại."}</pre></div>}
                    {latestReadJob?.status === "succeeded" && firewallRules.length === 0 && <div className="empty-state">Không tìm thấy firewall rule trên backend hiện tại.</div>}
                    {latestReadJob?.status === "succeeded" && firewallRules.length > 0 && filteredFirewallRules.length === 0 && <div className="empty-state">Không có rule nào khớp điều kiện tìm kiếm và bộ lọc.</div>}
                    {latestReadJob?.status === "succeeded" && firewallScan.warning && <div className="firewall-scan-warning"><b>Agent {server.agentVersion || "chưa rõ phiên bản"}</b><span>{firewallScan.warning}</span></div>}
                  </div>
                  <p className="firewall-note">Rule mới được xếp hàng ngay và chèn đầu chain UFW/nftables/iptables; sau mọi kết quả thêm, xóa hoặc đổi thứ tự, hệ thống tự quét lại danh sách thật từ Agent. Agent vẫn từ chối nếu zone/chain hoặc snapshot đã cũ. Windows Firewall không hỗ trợ thứ tự do quản trị viên gán: Block xung đột vẫn ưu tiên hơn Allow. Firewalld dùng priority và các chain hành động riêng nên chưa cho kéo để tránh tạo cảm giác sai về thứ tự thực thi.</p>
                </section>
              )}

              {activeTab === "updates" && (
                <UpdatesResourceTab key={successfulUpdateScanJobs[0]?.id ?? "updates-empty"} scans={successfulUpdateScanJobs} job={latestReadJob} serverName={server.name} osFamily={server.osFamily} busy={busy || readOnly} refresh={() => void refreshCurrentTab()} queue={runResourceAction} />
              )}

              {activeTab === "processes" && (
                <ProcessesResourceTab output={latestSuccessfulReadJob?.output} job={latestReadJob} serverName={server.name} busy={busy || readOnly} refresh={() => void refreshCurrentTab()} queue={runResourceAction} />
              )}

              {activeTab === "logs" && (
                <LogsResourceTab output={latestSuccessfulReadJob?.output} sourceOutput={latestSuccessfulLogSourcesJob?.output} configured={configuredLogSources} job={latestReadJob} serverName={server.name} busy={busy || readOnly} refresh={() => void refreshCurrentTab()} saveSources={saveLogSources} canConfigure={canConfigureLogs} />
              )}
            </>
          )}

          {activeTab === "files" && (
            <>
          <h3>Truyền file một chiều an toàn</h3>
          <form className="server-action-form secure-file-form" onSubmit={uploadFile}>
            <label>
              File đưa vào inbox cách ly
              <input name="file" type="file" required />
            </label>
            <label>
              Lý do / ticket
              <textarea name="reason" required minLength={5} rows={2} placeholder="CHG-1234 · Mục đích sử dụng file" />
            </label>
            <div className="warning-box">
              <b>Không đi qua SFTP, RDP drive hoặc clipboard</b>
              <p>
                File tối đa 1 GiB, được kiểm tra an toàn trước khi truyền và được quét lại tại máy đích.
                Hệ thống không tự chạy file và không ghi đè file đã có.
              </p>
            </div>
            <button className="button primary" disabled={fileBusy || !permissions.includes("files.manage") || !server.tunnelOnline}>
              {fileBusy ? "Đang quét…" : "Quét & gửi vào vùng cách ly"}
            </button>
          </form>
          {transfers.length > 0 && (
            <div className="transfer-list">
              {transfers.slice(0, 5).map((transfer) => (
                <div key={transfer.id}>
                  <span>
                    <b>{transfer.filename}</b>
                    <small>{Math.ceil(transfer.sizeBytes / 1024)} KiB · SHA-256 {transfer.sha256.slice(0, 12)}…</small>
                  </span>
                  <em>{transfer.status}</em>
                </div>
              ))}
            </div>
          )}
            </>
          )}

        </div>
      </section>
      {firewallModal === "add" && (
        <FirewallAddModal
          key={`${server.id}:${latestFirewallJob?.id ?? "no-scan"}:${latestFirewallJob?.status ?? "pending"}`}
          server={server}
          scan={firewallScan}
          busy={busy || readOnly}
          close={closeFirewallModal}
          submit={submitFirewallRule}
        />
      )}
      {firewallModal === "delete" && (
        <div className="modal-backdrop">
          <button className="modal-dismiss" type="button" aria-label="Đóng xác nhận xóa firewall rule" onClick={closeFirewallModal} />
          <section className="modal firewall-modal delete-firewall-modal" role="dialog" aria-modal="true" aria-labelledby="delete-firewall-title">
            <div className="modal-head"><div><span className="modal-icon danger">−</span><div><h2 id="delete-firewall-title">Xác nhận xóa {selectedRules.length} rule</h2><p>{server.name} · hành động rủi ro cao</p></div></div><button type="button" aria-label="Đóng" onClick={closeFirewallModal}>×</button></div>
            <div className="firewall-delete-list">{selectedRules.map((rule) => <div key={firewallRuleKey(rule)}><b>{rule.name}</b><span>{rule.backend} · {rule.direction} · {rule.action} · {rule.protocol}/{rule.localPort}</span><small>{rule.source} → {rule.destination}</small></div>)}</div>
            <label>Gõ <b>CONFIRM</b> để mở nút Delete<input value={firewallConfirmation} onChange={(event) => setFirewallConfirmation(event.target.value)} autoComplete="off" spellCheck={false} /></label>
            <div className="modal-actions"><button type="button" className="button ghost" onClick={closeFirewallModal}>Hủy</button>{firewallConfirmation === "CONFIRM" && <button type="button" className="button firewall-delete-button" disabled={busy} onClick={() => void deleteFirewallRules()}>{busy ? "Đang gửi…" : `Delete ${selectedRules.length} rule`}</button>}</div>
          </section>
        </div>
      )}
      {firewallModal === "reorder" && firewallReorder && (
        <div className="modal-backdrop">
          <button className="modal-dismiss" type="button" aria-label="Đóng xác nhận sắp xếp firewall rule" onClick={closeFirewallModal} />
          <form className="modal firewall-modal" onSubmit={submitFirewallReorder}>
            <div className="modal-head"><div><span className="modal-icon">↕</span><div><h2>Xác nhận đổi thứ tự rule</h2><p>{server.name} · tác vụ critical</p></div></div><button type="button" aria-label="Đóng" onClick={closeFirewallModal}>×</button></div>
            <div className="firewall-reorder-preview">
              <span>Di chuyển</span><b>{firewallReorder.rule.name}</b><small>{firewallReorder.rule.action} · {firewallReorder.rule.protocol}/{firewallReorder.rule.localPort} · {firewallReorder.rule.source} → {firewallReorder.rule.destination}</small>
              <span>{firewallReorder.before ? "Lên ngay trước" : "Xuống cuối nhóm"}</span><b>{firewallReorder.before?.name ?? firewallReorder.rule.orderGroup}</b>
            </div>
            <label>Lý do / ticket<textarea name="reason" required minLength={5} rows={2} placeholder="CHG-1234 · Đưa Allow SSH lên trước Deny" /></label>
            <div className="warning-box"><b>Kiểm tra tránh mất kết nối</b><p>Hãy xác nhận rule Allow quản trị cần thiết vẫn nằm trước Deny/Drop. Agent đối chiếu lại nội dung và vị trí rule ngay trước khi áp dụng; snapshot khác sẽ bị từ chối.</p></div>
            <div className="modal-actions"><button type="button" className="button ghost" onClick={closeFirewallModal}>Hủy</button><button className="button primary" disabled={busy}>{busy ? "Đang gửi…" : "Áp dụng thứ tự"}</button></div>
          </form>
        </div>
      )}
    </>
  );
}

function FirewallAddModal({
  server,
  scan,
  busy,
  close,
  submit,
}: {
  server: Server;
  scan: FirewallScan;
  busy: boolean;
  close: () => void;
  submit: (event: FormEvent<HTMLFormElement>) => Promise<void>;
}) {
  const backend = scan.backend || (server.osFamily === "windows" ? "windows" : "");
  const capabilities = firewallCapabilitiesForForm(scan);
  const initialTarget = capabilities.targets[0];
  const [targetId, setTargetId] = useState(initialTarget?.id ?? "");
  const [direction, setDirection] = useState<"in" | "out">(
    backend === "firewalld" ? "in" : initialTarget?.direction ?? "in",
  );
  const [ruleAction, setRuleAction] = useState("allow");
  const [protocol, setProtocol] = useState("tcp");
  const [servicePreset, setServicePreset] = useState("https");
  const [servicePort, setServicePort] = useState("443");
  const [remoteMode, setRemoteMode] = useState("any");
  const [remoteAddress, setRemoteAddress] = useState("");
  const [family, setFamily] = useState("ipv4");
  const [profile, setProfile] = useState(
    capabilities.activeProfiles[0] ?? capabilities.profiles[0] ?? "Any",
  );
  const [zone, setZone] = useState(capabilities.defaultZone || capabilities.zones[0] || "");
  const target = capabilities.targets.find((item) => item.id === targetId) ?? initialTarget;
  const needsTarget = backend === "nftables" || backend === "iptables";
  const scopeReady = Boolean(
    backend &&
    (backend !== "firewalld" || zone) &&
    (!needsTarget || target),
  );
  const remoteValue = remoteMode === "cidr" ? remoteAddress : "any";
  const expectedIpVersion = backend === "firewalld"
    ? family === "ipv6" ? 6 : 4
    : target?.family === "ip6" || target?.family === "ipv6"
      ? 6
      : target?.family === "ip" || target?.family === "ipv4"
        ? 4
        : null;
  const remoteIpVersion = remoteAddress.includes(":") ? 6 : 4;
  const addressFamilyMismatch = remoteMode === "cidr" && Boolean(remoteAddress) && expectedIpVersion !== null && remoteIpVersion !== expectedIpVersion;
  const formReady = scopeReady && !addressFamilyMismatch;
  const windowsOutbound = backend === "windows" && direction === "out";
  const localPort = windowsOutbound ? "any" : servicePort;
  const remotePort = windowsOutbound ? servicePort : "any";
  const source = direction === "in" || backend === "windows" ? remoteValue : "any";
  const destination = direction === "out" && backend !== "windows" ? remoteValue : "any";
  const backendDescriptions: Record<string, string> = {
    windows: "Profile được Agent đọc bằng Get-NetFirewallProfile trên đúng Windows Server này.",
    ufw: "UFW tự ánh xạ Inbound/Outbound sang chain phù hợp; không cần nhập table hoặc chain.",
    firewalld: "public là zone của firewalld, không phải chain. Danh sách zone bên dưới lấy trực tiếp từ máy chủ.",
    nftables: "Chỉ base chain loại filter có hook INPUT/OUTPUT lấy từ nftables được phép chọn; chain NAT/DOCKER bị loại.",
    iptables: "INPUT/OUTPUT là chain. UI chỉ cho chọn chain filter đang tồn tại do Agent báo về.",
  };
  const backendDescription = backendDescriptions[backend] ?? "Đang chờ Agent quét backend firewall và trả metadata từ máy chủ.";
  const scopeText = !backend
    ? "Chưa xác định backend"
    : backend === "windows"
      ? `Profile ${profile}`
      : backend === "firewalld"
        ? `Zone ${zone || "chưa có"} · ${family}`
        : needsTarget
          ? target?.label ?? "Chưa có filter chain phù hợp"
          : "UFW tự chọn chain";

  function selectService(value: string) {
    setServicePreset(value);
    const preset: Record<string, [string, string]> = {
      ssh: ["22", "tcp"],
      http: ["80", "tcp"],
      https: ["443", "tcp"],
      dns: ["53", "udp"],
      rdp: ["3389", "tcp"],
    };
    if (preset[value]) {
      setServicePort(preset[value][0]);
      setProtocol(preset[value][1]);
    }
  }

  function selectTarget(value: string) {
    setTargetId(value);
    const selected = capabilities.targets.find((item) => item.id === value);
    if (selected) setDirection(selected.direction);
  }

  return (
    <div className="modal-backdrop firewall-add-backdrop">
      <button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại thêm firewall rule" onClick={close} />
      <form className="modal firewall-modal add-firewall-modal" onSubmit={submit}>
        <div className="modal-head firewall-add-head">
          <div><span className="modal-icon">+</span><div><h2>Thêm firewall rule</h2><p>{server.name} · {backend || "đang chờ quét backend"}</p></div></div>
          <button type="button" aria-label="Đóng" onClick={close}>×</button>
        </div>

        <div className="firewall-add-scroll">
          <div className={`firewall-capability-note ${scopeReady ? "ready" : "waiting"}`}>
            <span>{scopeReady ? "✓ Dữ liệu trực tiếp từ máy chủ" : "! Chưa đủ metadata từ Agent"}</span>
            <b>{scopeText}</b>
            <p>{backendDescription}</p>
          </div>

          <input type="hidden" name="backend" value={backend} />
          <input type="hidden" name="direction" value={direction} />
          <input type="hidden" name="action" value={ruleAction} />
          <input type="hidden" name="protocol" value={protocol} />
          <input type="hidden" name="local_port" value={localPort} />
          <input type="hidden" name="remote_port" value={remotePort} />
          <input type="hidden" name="source" value={source} />
          <input type="hidden" name="destination" value={destination} />
          {target && <>
            <input type="hidden" name="family" value={target.family} />
            <input type="hidden" name="table" value={target.table} />
            <input type="hidden" name="chain" value={target.chain} />
          </>}

          <div className="firewall-add-grid">
            <label className="wide">
              Tên dễ nhận biết
              <input name="name" required minLength={1} maxLength={128} placeholder="VD: HTTPS từ mạng quản trị" />
              <small>Tên này xuất hiện trong lịch sử tác vụ và comment/display name của firewall.</small>
            </label>

            {backend === "windows" && <label className="wide">
              Profile Windows Firewall
              <select name="profile" value={profile} onChange={(event) => setProfile(event.target.value)} required>
                {capabilities.profiles.map((item) => <option key={item} value={item}>{item}{capabilities.activeProfiles.includes(item) ? " · đang bật" : ""}</option>)}
              </select>
              <small>Danh sách profile do chính Windows Server trả về.</small>
            </label>}

            {backend === "firewalld" && <>
              <label>
                Zone firewalld
                <select name="zone" value={zone} onChange={(event) => setZone(event.target.value)} required>
                  {capabilities.zones.map((item) => <option key={item} value={item}>{item}{item === capabilities.defaultZone ? " · mặc định" : ""}</option>)}
                </select>
                <small>Ví dụ public là zone; không phải INPUT/chain.</small>
              </label>
              <label>
                IP family
                <select name="family" value={family} onChange={(event) => setFamily(event.target.value)}>
                  <option value="ipv4">IPv4</option><option value="ipv6">IPv6</option>
                </select>
                <small>CIDR nhập bên dưới phải cùng family.</small>
              </label>
            </>}

            {needsTarget && <label className="wide">
              Filter chain trên máy chủ
              <select value={targetId} onChange={(event) => selectTarget(event.target.value)} required>
                {capabilities.targets.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
              </select>
              <small>Table và chain được lấy từ lần quét hiện tại; không cho nhập tay hoặc chọn NAT/DOCKER.</small>
            </label>}

            <label>
              Hướng lưu lượng
              <select value={direction} onChange={(event) => setDirection(event.target.value as "in" | "out")} disabled={backend === "firewalld" || needsTarget}>
                <option value="in">Đi vào máy chủ (Inbound)</option>
                {backend !== "firewalld" && <option value="out">Đi ra ngoài (Outbound)</option>}
              </select>
              <small>{needsTarget ? "Hướng được xác định bởi chain đã chọn." : "Chọn chiều kết nối cần kiểm soát."}</small>
            </label>
            <label>
              Hành động
              <select value={ruleAction} onChange={(event) => setRuleAction(event.target.value)}>
                <option value="allow">Cho phép (Allow)</option>
                <option value="deny">Chặn (Deny/Block)</option>
                {backend !== "windows" && <option value="reject">Từ chối có phản hồi (Reject)</option>}
              </select>
              <small>Agent chuyển sang action tương ứng của backend.</small>
            </label>

            <label>
              Dịch vụ phổ biến
              <select value={servicePreset} onChange={(event) => selectService(event.target.value)}>
                <option value="ssh">SSH · TCP 22</option><option value="http">HTTP · TCP 80</option>
                <option value="https">HTTPS · TCP 443</option><option value="dns">DNS · UDP 53</option>
                <option value="rdp">RDP · TCP 3389</option><option value="custom">Tự chọn</option>
              </select>
              <small>Preset tự điền cổng và protocol.</small>
            </label>
            <div className="firewall-port-grid">
              <label>
                {direction === "in" ? "Cổng dịch vụ trên máy chủ" : "Cổng dịch vụ từ xa"}
                <input type="number" min="1" max="65535" value={servicePort} onChange={(event) => { setServicePort(event.target.value); setServicePreset("custom"); }} required />
              </label>
              <label>
                Protocol
                <select value={protocol} onChange={(event) => { setProtocol(event.target.value); setServicePreset("custom"); }}><option value="tcp">TCP</option><option value="udp">UDP</option></select>
              </label>
            </div>

            <label className="wide">
              {direction === "in" ? "Nguồn kết nối từ xa" : "Đích kết nối từ xa"}
              <select value={remoteMode} onChange={(event) => setRemoteMode(event.target.value)}>
                <option value="any">Mọi địa chỉ (any)</option><option value="cidr">Chỉ một IP/mạng cụ thể</option>
              </select>
              <small>{direction === "in" ? "Giới hạn mạng được phép kết nối vào máy chủ." : "Giới hạn mạng đích mà máy chủ được kết nối tới."}</small>
            </label>
            {remoteMode === "cidr" && <label className="wide">
              CIDR IPv4/IPv6
              <input value={remoteAddress} onChange={(event) => setRemoteAddress(event.target.value)} required placeholder="VD: 10.20.0.0/16 hoặc 2001:db8::/64" />
              <small className={addressFamilyMismatch ? "field-error" : ""}>{addressFamilyMismatch ? `Địa chỉ này không khớp ${expectedIpVersion === 6 ? "IPv6" : "IPv4"} của zone/chain đã chọn.` : "IP đơn dùng /32 (IPv4) hoặc /128 (IPv6)."}</small>
            </label>}

            <label className="wide">
              Lý do / ticket
              <textarea name="reason" required minLength={5} rows={2} placeholder="CHG-1234 · Cho phép HTTPS từ mạng quản trị" />
            </label>
          </div>

          <div className="firewall-rule-preview">
            <span>Rule chuẩn bị gửi tới Agent</span>
            <b>{ruleAction.toUpperCase()} {protocol.toUpperCase()} {servicePort || "?"} · {direction === "in" ? "Inbound" : "Outbound"} · {remoteValue || "CIDR chưa nhập"}</b>
            <small>{scopeText}</small>
          </div>
          <div className="warning-box"><b>Thực thi trực tiếp có kiểm soát</b><p>Tác vụ được xếp hàng ngay. Agent sẽ kiểm tra lại zone/chain vẫn tồn tại và CIDR hợp lệ trước khi áp dụng.</p></div>
        </div>

        <div className="modal-actions firewall-add-actions">
          <button type="button" className="button ghost" onClick={close}>Hủy</button>
          <button className="button primary" disabled={busy || !formReady}>{busy ? "Đang thêm…" : addressFamilyMismatch ? "CIDR không đúng IP family" : scopeReady ? "Thêm Rule" : "Cần nâng cấp Agent và quét lại"}</button>
        </div>
      </form>
    </div>
  );
}

function SessionsView({ token }: { token: string }) {
  const [items, setItems] = useState<
    Array<{
      id: string;
      serverName: string;
      protocol: string;
      username: string;
      createdBy: string;
      status: string;
      startedAt: string;
    }>
  >([]);
  useEffect(() => {
    fetch("/api/v1/sessions", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((data) => setItems(data.items ?? []))
      .catch(() => setItems([]));
  }, [token]);
  return (
    <section className="panel view-panel">
      <div className="panel-head">
        <div>
          <h2>Lịch sử phiên truy cập</h2>
          <p>
            Mọi phiên đều được ghi nhận và gắn với danh tính người vận hành.
          </p>
        </div>
        <span className="live-pill">
          <i />
          {items.filter((item) => item.status === "launched").length} đã khởi
          tạo
        </span>
      </div>
      <div className="session-list">
        {items.length ? (
          items.map((item) => (
            <article key={item.id}>
              <span className={`session-protocol ${item.protocol}`}>
                {item.protocol.toUpperCase()}
              </span>
              <div>
                <b>{item.serverName}</b>
                <small>
                  {item.username} · {item.createdBy}
                </small>
              </div>
              <time>{new Date(item.startedAt).toLocaleString("vi-VN")}</time>
              <span className="recording">● CÓ GHI</span>
              <span />
            </article>
          ))
        ) : (
          <div className="empty-state">
            Chưa có phiên truy cập nào.
          </div>
        )}
      </div>
    </section>
  );
}

function JobsView({ token, servers }: { token: string; servers: Server[] }) {
  const [jobs, setJobs] = useState<JobListRow[]>([]);
  const [jobSearch, setJobSearch] = useState("");
  const serversById = useMemo(() => new Map(servers.map((server) => [server.id, server])), [servers]);
  const serverIdentity = (job: JobListRow) => {
    const currentServer = serversById.get(job.serverId);
    const hostname = currentServer?.name || job.serverName || job.serverId.slice(0, 8);
    const address = currentServer?.address || job.serverAddress || "chưa có IP";
    return { hostname, address };
  };
  useEffect(() => {
    fetch("/api/v1/jobs", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((data) => setJobs(data.items ?? []))
      .catch(() => setJobs([]));
  }, [token]);
  const statusLabel = (status: string) =>
    ({
      pending_approval: "Job cũ chưa chạy",
      cancelled: "Đã hủy",
      queued: "Đang chờ agent",
      dispatched: "Đang chạy",
      succeeded: "Hoàn tất",
      failed: "Thất bại",
    })[status] ?? status;
  const normalizedJobSearch = normalizeSearchText(jobSearch);
  const visibleJobs = normalizedJobSearch
    ? jobs.filter((job) => {
        const identity = serverIdentity(job);
        return normalizeSearchText([
          jobActionLabel(job.action),
          job.action,
          job.reason,
          identity.hostname,
          identity.address,
          job.risk,
          statusLabel(job.status),
          job.status,
          new Date(job.createdAt).toLocaleString("vi-VN"),
        ].join(" ")).includes(normalizedJobSearch);
      })
    : jobs;
  return (
    <section className="panel view-panel">
      <div className="panel-head">
        <div>
          <h2>Luồng công việc</h2>
          <p>Theo dõi trạng thái và kết quả thao tác trên các máy chủ.</p>
        </div>
      </div>
      <div className="jobs-toolbar">
        <label>
          Tìm kiếm công việc
          <input
            className="resource-search"
            value={jobSearch}
            onChange={(event) => setJobSearch(event.target.value)}
            maxLength={160}
            placeholder="Từ/cụm từ tiếng Việt hoặc English, hostname, IP…"
          />
        </label>
        <span>{visibleJobs.length}/{jobs.length} công việc</span>
      </div>
      <div className="jobs-table">
        <div className="jobs-row head">
          <span>Công việc</span>
          <span>Máy chủ</span>
          <span>Mức rủi ro</span>
          <span>Thời điểm</span>
          <span>Trạng thái</span>
        </div>
        {visibleJobs.length ? (
          visibleJobs.map((job) => {
            const identity = serverIdentity(job);
            return <div className="jobs-row" key={job.id}>
              <p>
                <b title={job.action}>{jobActionLabel(job.action)}</b>
                <small>{job.reason}</small>
              </p>
              <span className="job-server-label">
                <strong className="job-server-hostname">{identity.hostname}</strong>
                <span className="job-server-address">[{identity.address}]</span>
              </span>
              <span>{job.risk}</span>
              <time>{new Date(job.createdAt).toLocaleString("vi-VN")}</time>
              <div className="job-controls">
                <span
                  className={`job-state ${job.status === "succeeded" ? "done" : ["queued", "dispatched"].includes(job.status) ? "running" : "pending"}`}
                >
                  {statusLabel(job.status)}
                </span>
              </div>
              {job.status === "failed" && (
                <pre className="job-error-output">Exit code {job.exitCode ?? "?"}{"\n"}{job.output || "Agent không trả về nội dung lỗi."}</pre>
              )}
            </div>;
          })
        ) : (
          <div className="empty-state">
            {jobs.length ? "Không tìm thấy công việc phù hợp." : "Chưa có công việc nào."}
          </div>
        )}
      </div>
    </section>
  );
}

type SessionRecord = {
  id: string;
  serverName: string;
  protocol: string;
  username: string;
  createdBy: string;
  status: string;
  recordingAvailable: boolean;
  recordingDeletable?: boolean;
  recordingSizeBytes: number;
  recordingStatus?: string;
  startedAt: string;
  finishedAt?: string | null;
};

type RecordingDeletionRequest = {
  id: string;
  sessionIds: string[];
  sessions: Array<{ id: string; label: string }>;
  reason: string;
  status: "pending" | "deleting" | "deleted" | "failed";
  requestedBy: string;
  requestedByUsername: string;
  approvedBy?: string | null;
  approvedByUsername?: string;
  createdAt: string;
  error?: string;
};

function RecordingPlayer({
  session,
  token,
  close,
}: {
  session: SessionRecord;
  token: string;
  close: () => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const player = useRef<InstanceType<typeof Guacamole.SessionRecording> | null>(
    null,
  );
  const [playing, setPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!host.current) return;
    const tunnel = new Guacamole.StaticHTTPTunnel(
      `/api/v1/sessions/${session.id}/recording`,
      false,
      { Authorization: `Bearer ${token}` },
    );
    const recording = new Guacamole.SessionRecording(tunnel);
    player.current = recording;
    const display = recording.getDisplay();
    const element = display.getElement();
    host.current.replaceChildren(element);
    const fit = () => {
      if (host.current && display.getWidth() > 0 && display.getHeight() > 0)
        display.scale(
          Math.min(
            host.current.clientWidth / display.getWidth(),
            host.current.clientHeight / display.getHeight(),
          ),
        );
    };
    recording.onprogress = (nextDuration: number) => {
      setDuration(nextDuration);
      fit();
    };
    recording.onseek = (nextPosition: number) => {
      setPosition(nextPosition);
      fit();
    };
    recording.onplay = () => setPlaying(true);
    recording.onpause = () => setPlaying(false);
    recording.onerror = () =>
      setError(
        "Không thể tải recording. Kiểm tra file recording và quyền thư mục trên host.",
      );
    window.addEventListener("resize", fit);
    recording.connect();
    return () => {
      window.removeEventListener("resize", fit);
      recording.abort();
      player.current = null;
    };
  }, [session.id, token]);
  function toggle() {
    if (!player.current) return;
    if (playing) player.current.pause();
    else player.current.play();
  }
  function seek(next: number) {
    player.current?.seek(next, () => setPosition(next));
  }
  return (
    <div className="modal-backdrop recording-backdrop">
      <button
        className="modal-dismiss"
        type="button"
        aria-label="Đóng trình phát"
        onClick={close}
      />
      <section className="recording-player">
        <header>
          <div>
            <b>{session.serverName}</b>
            <small>
              {session.protocol.toUpperCase()} · {session.username} ·{" "}
              {new Date(session.startedAt).toLocaleString("vi-VN")}
            </small>
          </div>
          <button onClick={close}>×</button>
        </header>
        <div ref={host} className="recording-screen">
          {error && <p>{error}</p>}
        </div>
        <footer>
          <button className="button primary" onClick={toggle}>
            {playing ? "Tạm dừng" : "Phát"}
          </button>
          <input
            aria-label="Vị trí phát"
            type="range"
            min={0}
            max={Math.max(duration, 1)}
            value={Math.min(position, duration)}
            onChange={(event) => seek(Number(event.target.value))}
          />
          <time>
            {Math.floor(position / 60000)}:
            {String(Math.floor(position / 1000) % 60).padStart(2, "0")} /{" "}
            {Math.floor(duration / 60000)}:
            {String(Math.floor(duration / 1000) % 60).padStart(2, "0")}
          </time>
        </footer>
      </section>
    </div>
  );
}

function auditDetailText(detail: Record<string, unknown>) {
  return Object.entries(detail ?? {})
    .filter(([key]) => !hiddenAuditDetailKeys.has(key.toLocaleLowerCase("en-US")))
    .map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`)
    .join(" · ");
}

function AuditView({ token }: { token: string }) {
  const [rows, setRows] = useState<
    Array<{
      id: string;
      occurredAt: string;
      actor: string;
      action: string;
      target: string;
      result: string;
      sourceIp: string;
      detail: Record<string, unknown>;
    }>
  >([]);
  const [auditNextBefore, setAuditNextBefore] = useState<string | null>(null);
  const [auditRetentionDays, setAuditRetentionDays] = useState(30);
  const [auditBusy, setAuditBusy] = useState(false);
  const [auditSearch, setAuditSearch] = useState("");
  const [auditResult, setAuditResult] = useState("");
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [deletionRequests, setDeletionRequests] = useState<RecordingDeletionRequest[]>([]);
  const [currentUser, setCurrentUser] = useState<{ id: string; username: string; role: string; permissions: string[] } | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [tab, setTab] = useState<"events" | "recordings">("events");
  const [selectedRecording, setSelectedRecording] =
    useState<SessionRecord | null>(null);
  const [selectedRecordingIds, setSelectedRecordingIds] = useState<string[]>([]);
  const [deleteModal, setDeleteModal] = useState(false);
  const [deleteReason, setDeleteReason] = useState("");
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [deleteValidation, setDeleteValidation] = useState("");
  const [retention, setRetention] = useState<{ enabled: boolean; days: number; lastRun?: { ranAt?: string; deletedFiles?: number; errors?: number } }>({ enabled: true, days: 180 });
  const [retentionModal, setRetentionModal] = useState(false);
  const [recordingBusy, setRecordingBusy] = useState(false);
  const [recordingMessage, setRecordingMessage] = useState("");
  const sessionLoadGeneration = useRef(0);
  const deletionLoadGeneration = useRef(0);
  const pendingRecordingIds = useRef(new Set<string>());
  const loadSessions = useCallback(async () => {
    const generation = ++sessionLoadGeneration.current;
    try {
      const response = await fetch("/api/v1/sessions", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
      if (!response.ok) throw new Error("Không tải được danh sách video. Hãy làm mới để thử lại.");
      const data = await response.json();
      if (generation !== sessionLoadGeneration.current) return;
      const updated: SessionRecord[] = data.items ?? [];
      const selectableIds = new Set(updated.filter((item) => ["closed", "failed"].includes(item.status)
        && (item.recordingDeletable ?? item.recordingAvailable) && !pendingRecordingIds.current.has(item.id)).map((item) => item.id));
      const ids = new Set(updated.map((item) => item.id));
      setSessions(updated);
      setSelectedRecordingIds((selected) => selected.filter((id) => selectableIds.has(id)));
      setSelectedRecording((selected) => selected && ids.has(selected.id) ? selected : null);
    } catch (error) {
      if (generation === sessionLoadGeneration.current)
        setRecordingMessage(error instanceof Error ? error.message : "Không tải được danh sách video.");
    }
  }, [token]);
  const loadDeletionRequests = useCallback(async () => {
    const generation = ++deletionLoadGeneration.current;
    try {
      const response = await fetch("/api/v1/recording-deletion-requests", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
      if (!response.ok) return;
      const data = await response.json();
      if (generation !== deletionLoadGeneration.current) return;
      const updated: RecordingDeletionRequest[] = data.items ?? [];
      const pending = new Set(updated.filter((item) => ["pending", "deleting"].includes(item.status)).flatMap((item) => item.sessionIds));
      pendingRecordingIds.current = pending;
      setDeletionRequests(updated);
      setSelectedRecordingIds((selected) => selected.filter((id) => !pending.has(id)));
    } catch { /* Keep the last list on a transient read failure. */ }
  }, [token]);
  const loadRecordingRetention = useCallback(() =>
    fetch("/api/v1/settings/recording-retention", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((data) => setRetention({ enabled: data.enabled !== false, days: Number(data.days) || 180, lastRun: data.lastRun }))
      .catch(() => undefined), [token]);
  const loadAudit = useCallback(async (before?: string) => {
    setAuditBusy(true);
    try {
      const query = new URLSearchParams();
      if (before) query.set("before", before);
      if (auditResult) query.set("result", auditResult);
      const response = await fetch(`/api/v1/audit?${query.toString()}`, { headers: { Authorization: `Bearer ${token}` } });
      if (response.status === 403) setForbidden(true);
      if (!response.ok) throw new Error("audit-unavailable");
      const data = await response.json();
      setForbidden(false);
      setRows((current) => before ? [...current, ...(data.items ?? [])] : (data.items ?? []));
      setAuditNextBefore(data.nextBefore ?? null);
      setAuditRetentionDays(Number(data.retentionDays) || 30);
    } catch {
      if (!before) setRows([]);
    } finally {
      setAuditBusy(false);
    }
  }, [auditResult, token]);
  useEffect(() => {
    const sessionsGeneration = sessionLoadGeneration, requestsGeneration = deletionLoadGeneration;
    fetch("/api/v1/me", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then(setCurrentUser)
      .catch(() => setCurrentUser(null));
    const initial = window.setTimeout(() => { void loadSessions(); void loadDeletionRequests(); void loadRecordingRetention(); }, 0);
    return () => { ++sessionsGeneration.current; ++requestsGeneration.current; window.clearTimeout(initial); };
  }, [token, loadSessions, loadDeletionRequests, loadRecordingRetention]);
  useEffect(() => {
    const auditTimer = window.setTimeout(() => void loadAudit(), 300);
    return () => window.clearTimeout(auditTimer);
  }, [loadAudit]);
  useEffect(() => {
    if (tab !== "recordings") return;
    const refresh = () => { void loadSessions(); void loadDeletionRequests(); };
    const initial = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 10000);
    window.addEventListener("focus", refresh);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); window.removeEventListener("focus", refresh); };
  }, [tab, loadSessions, loadDeletionRequests]);
  const normalizedAuditSearch = normalizeSearchText(auditSearch);
  const visibleAuditRows = useMemo(() => normalizedAuditSearch
    ? rows.filter((row) => normalizeSearchText([
        row.actor,
        auditActionLabel(row.action, row.detail),
        row.action,
        auditTargetLabel(row.target),
        auditDetailText(row.detail),
        auditResultLabels[row.result] ?? row.result,
        row.result,
        row.sourceIp,
        new Date(row.occurredAt).toLocaleString("vi-VN"),
      ].join(" ")).includes(normalizedAuditSearch))
    : rows, [normalizedAuditSearch, rows]);
  const pendingSessionIds = new Set(deletionRequests.filter((item) => ["pending", "deleting"].includes(item.status)).flatMap((item) => item.sessionIds));
  const selectableSessions = sessions.filter((session) => ["closed", "failed"].includes(session.status) && (session.recordingDeletable ?? session.recordingAvailable) && !pendingSessionIds.has(session.id));
  const selectableBatch = selectableSessions.slice(0, 100);
  const selectedSessions = sessions.filter((session) => selectedRecordingIds.includes(session.id));
  function toggleRecording(sessionId: string) {
    setSelectedRecordingIds((current) => current.includes(sessionId) ? current.filter((item) => item !== sessionId) : current.length < 100 ? [...current, sessionId] : current);
  }
  async function requestRecordingDeletion() {
    if (selectedRecordingIds.length === 0) return setDeleteValidation("Hãy chọn ít nhất một recording còn khả dụng.");
    if (deleteReason.trim().length < 5) return setDeleteValidation("Lý do / ticket là bắt buộc và phải có ít nhất 5 ký tự.");
    if (deleteConfirmation !== "DELETE") return setDeleteValidation("Hãy gõ chính xác DELETE để xác nhận tạo yêu cầu.");
    setRecordingBusy(true);
    setDeleteValidation("");
    setRecordingMessage("");
    try {
      const response = await fetch("/api/v1/recording-deletion-requests", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ session_ids: selectedRecordingIds, reason: deleteReason }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) return setDeleteValidation(data.detail ?? "Không thể tạo yêu cầu xóa recording.");
      setRecordingMessage("Đã gửi đến Phê duyệt. Video sẽ được xóa khi một quản trị viên khác duyệt.");
      setSelectedRecordingIds([]);
      setDeleteModal(false);
      setDeleteReason("");
      setDeleteConfirmation("");
      await loadDeletionRequests();
    } catch {
      setDeleteValidation("Không kết nối được hệ thống. Hãy thử lại; chưa có yêu cầu nào được tạo.");
    } finally {
      setRecordingBusy(false);
    }
  }
  async function saveRecordingRetention(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const enabled = form.get("enabled") === "on";
    const days = Number(form.get("days"));
    if (!Number.isInteger(days) || days < 30 || days > 3650) return setRecordingMessage("Số ngày lưu recording phải từ 30 đến 3650 ngày.");
    setRecordingBusy(true);
    setRecordingMessage("");
    try {
      const response = await fetch("/api/v1/settings/recording-retention", {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ enabled, days }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? "Không thể lưu thời gian lưu recording");
      setRetention({ enabled: data.enabled !== false, days: Number(data.days) || days, lastRun: data.lastRun });
      setRetentionModal(false);
      setRecordingMessage(enabled ? `Đã bật tự động xóa recording cũ hơn ${days} ngày.` : "Đã tắt tự động xóa recording.");
      await loadSessions();
    } catch (error) {
      setRecordingMessage(error instanceof Error ? error.message : "Không thể lưu thời gian lưu recording.");
    } finally {
      setRecordingBusy(false);
    }
  }
  return (
    <>
      <section className="panel view-panel">
        <div className="panel-head">
          <div>
            <h2>Nhật ký kiểm toán</h2>
            <p>Ghi nhận thao tác người dùng và tự động dọn dữ liệu cũ sau {auditRetentionDays} ngày.</p>
          </div>
          <div className="audit-integrity">◆ Chuỗi hash liên kết</div>
        </div>
        <div className="audit-tabs">
          <button
            className={tab === "events" ? "active" : ""}
            onClick={() => setTab("events")}
          >
            Sự kiện audit
          </button>
          {currentUser?.permissions.includes("recordings.view") && <button
            className={tab === "recordings" ? "active" : ""}
            onClick={() => setTab("recordings")}
          >
            Video ghi session
          </button>}
        </div>
        {tab === "events" ? (
          <div className="audit-events-panel">
            <div className="audit-filter-bar">
              <label>Tìm kiếm<input value={auditSearch} onChange={(event) => setAuditSearch(event.target.value)} maxLength={160} placeholder="Từ/cụm từ tiếng Việt hoặc English, người dùng, đối tượng, IP…" /></label>
              <label>Kết quả<select value={auditResult} onChange={(event) => setAuditResult(event.target.value)}><option value="">Tất cả</option><option value="success">Thành công</option><option value="denied">Bị từ chối</option><option value="failed">Thất bại</option><option value="partial">Một phần</option><option value="cancelled">Đã hủy</option></select></label>
              <button type="button" className="button ghost" disabled={auditBusy} onClick={() => void loadAudit()}>{auditBusy ? "Đang lọc…" : "↻ Làm mới"}</button>
            </div>
            <div className="audit-table">
              <div className="audit-row head">
                <span>Thời gian</span>
                <span>Chủ thể</span>
                <span>Hành động</span>
                <span>Đối tượng</span>
                <span>Chi tiết thao tác</span>
                <span>Kết quả</span>
                <span>IP nguồn</span>
              </div>
              {visibleAuditRows.length ? (
                visibleAuditRows.map((row) => (
                  <div className="audit-row" key={row.id}>
                    <time>
                      {new Date(row.occurredAt).toLocaleString("vi-VN")}
                    </time>
                    <b>{row.actor}</b>
                    <span title={row.action}>{auditActionLabel(row.action, row.detail)}</span>
                    <span>{auditTargetLabel(row.target)}</span>
                    <span className="audit-detail">{auditDetailText(row.detail) || "—"}</span>
                    <span
                      className={
                        row.result === "success" ? "result-good" : "result-warn"
                      }
                    >
                      {auditResultLabels[row.result] ?? row.result}
                    </span>
                    <span>{row.sourceIp || "—"}</span>
                  </div>
                ))
              ) : (
                <div className="empty-state">
                  {forbidden
                    ? "Vai trò hiện tại không có quyền đọc audit."
                    : rows.length
                      ? "Không tìm thấy nhật ký phù hợp."
                      : "Chưa có sự kiện kiểm toán."}
                </div>
              )}
            </div>
            {auditNextBefore && <div className="audit-load-more"><button type="button" className="button ghost" disabled={auditBusy} onClick={() => void loadAudit(auditNextBefore)}>{auditBusy ? "Đang tải..." : "Tải thêm nhật ký"}</button></div>}
          </div>
        ) : (
          <div className="recording-management">
            {currentUser?.permissions?.some((permission) => ["recordings.delete", "deletions.request"].includes(permission)) && (
              <div className="recording-actions">
                <label><input type="checkbox" checked={selectableBatch.length > 0 && selectableBatch.every((session) => selectedRecordingIds.includes(session.id))} onChange={() => setSelectedRecordingIds(selectableBatch.every((session) => selectedRecordingIds.includes(session.id)) ? [] : selectableBatch.map((session) => session.id))} /> Chọn video có thể xóa (tối đa 100)</label>
                <span>{selectedRecordingIds.length} video đang chọn</span>
                {currentUser.role === "admin" && <><span>{retention.enabled ? `Tự động xóa sau ${retention.days} ngày` : "Tự động xóa đang tắt"}</span><button className="resource-icon-button settings" type="button" title="Cấu hình thời gian lưu recording" onClick={() => setRetentionModal(true)}>⚙</button></>}
                <button className="button danger" disabled={selectedRecordingIds.length === 0} onClick={() => { setDeleteValidation(""); setDeleteModal(true); }}>Xóa video đã chọn</button>
              </div>
            )}
            {recordingMessage && <div className="recording-message">{recordingMessage}</div>}
            <div className="recording-actions">
              <button className="button ghost" onClick={() => { void loadSessions(); void loadDeletionRequests(); }}>Làm mới</button>
              {currentUser?.permissions?.some((permission) => ["recordings.delete", "deletions.request"].includes(permission)) &&
                <a className="button ghost" href="#/approvals">Xem yêu cầu tại Phê duyệt</a>}
            </div>
            <div className="recording-list audit-recordings">
            {sessions.length ? (
              sessions.map((session) => (
                <div key={session.id}>
                  {currentUser?.permissions?.some((permission) => ["recordings.delete", "deletions.request"].includes(permission)) ? <input type="checkbox" checked={selectedRecordingIds.includes(session.id)} disabled={!selectableSessions.some((item) => item.id === session.id)} aria-label={`Chọn recording ${session.serverName}`} onChange={() => toggleRecording(session.id)} /> : <span />}
                  <span className="play">▶</span>
                  <p>
                    <b>
                      {session.serverName} · {session.protocol.toUpperCase()}
                    </b>
                    <small>
                      {session.username} · {session.createdBy} ·{" "}
                      {new Date(session.startedAt).toLocaleString("vi-VN")}
                      {session.recordingAvailable && ` · ${(session.recordingSizeBytes / 1024 / 1024).toFixed(1)} MiB`}
                    </small>
                  </p>
                  <span
                    className={
                      session.recordingAvailable
                        ? "verified"
                        : "recording-pending"
                    }
                  >
                    {pendingSessionIds.has(session.id)
                      ? "Chờ duyệt xóa"
                      : session.recordingAvailable
                        ? "● Sẵn sàng"
                        : session.recordingStatus === "permission_denied"
                          ? "API không có quyền đọc file"
                          : ["root_missing", "root_invalid", "root_unreadable"].includes(session.recordingStatus ?? "")
                            ? "Volume recording chưa sẵn sàng"
                            : session.recordingStatus === "empty"
                              ? "File recording đang trống"
                              : session.finishedAt ? "Không tìm thấy file" : "Đang ghi"}
                  </span>
                  <button
                    disabled={!session.recordingAvailable}
                    onClick={() => setSelectedRecording(session)}
                  >
                    Xem lại
                  </button>
                </div>
              ))
            ) : (
              <div className="empty-state">
                Chưa có phiên truy cập được ghi lại.
              </div>
            )}
            </div>
          </div>
        )}
      </section>
      {deleteModal && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setDeleteModal(false); }}>
          <section className="modal firewall-modal" role="dialog" aria-modal="true" aria-label="Yêu cầu xóa recording">
            <div className="modal-head"><div><span className="modal-icon danger">−</span><div><h2>Yêu cầu xóa {selectedSessions.length} video</h2><p>Cần một quản trị viên khác duyệt trước khi file bị xóa.</p></div></div><button type="button" onClick={() => setDeleteModal(false)}>×</button></div>
            <div className="firewall-delete-list">{selectedSessions.map((session) => <div key={session.id}><b>{session.serverName} · {session.protocol.toUpperCase()}</b><span>{session.username} · {new Date(session.startedAt).toLocaleString("vi-VN")}</span></div>)}</div>
            <label>Lý do / ticket <b>(bắt buộc)</b><textarea rows={3} minLength={5} value={deleteReason} onChange={(event) => { setDeleteReason(event.target.value); setDeleteValidation(""); }} placeholder="CHG-1234 · Lý do xóa recording" /></label>
            <label>Gõ DELETE để tạo yêu cầu<input value={deleteConfirmation} onChange={(event) => { setDeleteConfirmation(event.target.value); setDeleteValidation(""); }} autoComplete="off" /></label>
            {deleteValidation && <div className="danger-panel">{deleteValidation}</div>}
            <div className="modal-actions"><button type="button" className="button ghost" onClick={() => setDeleteModal(false)}>Hủy</button><button type="button" className="button danger" disabled={recordingBusy} onClick={() => void requestRecordingDeletion()}>{recordingBusy ? "Đang gửi..." : "Gửi yêu cầu xóa"}</button></div>
          </section>
        </div>
      )}
      {retentionModal && <ModalShell title="Tự động dọn recording" subtitle="Dọn file theo tuổi để bảo vệ dung lượng ổ đĩa; tác vụ hệ thống chạy trực tiếp, không cần phê duyệt" close={() => setRetentionModal(false)}><form className="resource-form" onSubmit={saveRecordingRetention}><label className="check"><input name="enabled" type="checkbox" defaultChecked={retention.enabled} /> Bật tự động xóa recording cũ</label><label>Thời gian lưu (ngày)<input name="days" type="number" min={30} max={3650} defaultValue={retention.days} required /></label><div className="resource-help">Mặc định 180 ngày (xấp xỉ 6 tháng). Khi lưu cấu hình, hệ thống dọn ngay các file đủ tuổi rồi tự kiểm tra lại mỗi 6 giờ. Recording đang được ghi không bị xóa.</div>{retention.lastRun?.ranAt && <div className="resource-help">Lần dọn gần nhất: {new Date(retention.lastRun.ranAt).toLocaleString("vi-VN")} · đã xóa {retention.lastRun.deletedFiles ?? 0} file{retention.lastRun.errors ? ` · ${retention.lastRun.errors} lỗi` : ""}</div>}<div className="modal-actions"><button type="button" className="button ghost" onClick={() => setRetentionModal(false)}>Hủy</button><button className="button primary" disabled={recordingBusy}>{recordingBusy ? "Đang lưu..." : "Lưu cấu hình"}</button></div></form></ModalShell>}
      {selectedRecording && (
        <RecordingPlayer
          session={selectedRecording}
          token={token}
          close={() => setSelectedRecording(null)}
        />
      )}
    </>
  );
}

type AgentUpgradeItem = {
  serverId: string;
  serverName: string;
  osFamily: OSFamily;
  architecture: string;
  currentVersion: string;
  eligibility: string;
  reason: string;
  activeJobId?: string | null;
  activeJobStatus?: string | null;
  targetVersion: string;
  online: boolean;
};

type AgentUpgradeStatus = {
  targetVersion: string;
  minimumSelfUpdateVersion: string;
  artifacts: unknown;
  items: AgentUpgradeItem[];
};

type AgentUninstallProtectionStatus = {
  configured: boolean;
  revision: number;
  updatedAt?: string | null;
  totalAgents: number;
  appliedAgents: number;
  pendingAgents: number;
  failedAgents: number;
  manualRequiredAgents: number;
};

const agentUpgradeStateLabels: Record<string, string> = {
  eligible: "Có bản mới",
  update_available: "Có bản mới",
  manual_required: "Cần nâng thủ công 1 lần",
  current: "Mới nhất",
  newer: "Mới hơn bản phát hành",
  offline: "Mất kết nối",
  unsupported: "Không hỗ trợ",
  queued: "Đang chờ Agent",
  dispatched: "Đang tải gói",
  installing: "Đang cài đặt",
  succeeded: "Đã cập nhật",
  failed: "Cập nhật thất bại",
};

function agentUpgradeState(item: AgentUpgradeItem) {
  const activeStatus = String(item.activeJobStatus || "").toLowerCase();
  if (["queued", "dispatched", "installing", "failed"].includes(activeStatus)) return activeStatus;
  const eligibility = String(item.eligibility || "unsupported").toLowerCase();
  return eligibility === "eligible" && item.online === false ? "offline" : eligibility;
}

function agentUpgradeIsActive(item: AgentUpgradeItem) {
  return ["queued", "dispatched", "installing"].includes(agentUpgradeState(item));
}

function agentUpgradeCanSelect(item: AgentUpgradeItem) {
  const eligibility = String(item.eligibility || "").toLowerCase();
  return ["eligible", "update_available"].includes(eligibility) && !agentUpgradeIsActive(item);
}

function agentManagementError(data: Record<string, unknown>, fallback: string) {
  if (typeof data.detail === "string") return data.detail;
  if (data.detail && typeof data.detail === "object" && "message" in data.detail && typeof (data.detail as { message?: unknown }).message === "string") return (data.detail as { message: string }).message;
  return fallback;
}

function AgentPackagesView({ token, canManageUninstallProtection }: { token: string; canManageUninstallProtection: boolean }) {
  const [status, setStatus] = useState<{
    dashboardUrl: string;
    agentVersion: string;
    linuxAvailable: boolean;
    linuxOfflineProfiles: Partial<Record<LinuxOfflineProfile, boolean>>;
    windowsMsiAvailable: boolean;
    agentTlsCaAvailable: boolean;
    claimTtlMinutes: number;
    webTlsTrust: "internal-ca" | "system";
  } | null>(null);
  const [busy, setBusy] = useState<OSFamily | null>(null);
  const [linuxProfile, setLinuxProfile] = useState<LinuxOfflineProfile>("ubuntu-24.04");
  const [message, setMessage] = useState("");
  const [messageIsError, setMessageIsError] = useState(false);
  const [upgradeStatus, setUpgradeStatus] = useState<AgentUpgradeStatus | null>(null);
  const [upgradeLoading, setUpgradeLoading] = useState(true);
  const [upgradeBusy, setUpgradeBusy] = useState(false);
  const [upgradeMessage, setUpgradeMessage] = useState("");
  const [upgradeMessageIsError, setUpgradeMessageIsError] = useState(false);
  const [upgradeSearch, setUpgradeSearch] = useState("");
  const [upgradeOsFilter, setUpgradeOsFilter] = useState<"all" | OSFamily>("all");
  const [upgradeStateFilter, setUpgradeStateFilter] = useState("all");
  const [selectedUpgradeServerIds, setSelectedUpgradeServerIds] = useState<string[]>([]);
  const [upgradeModal, setUpgradeModal] = useState(false);
  const [upgradeReason, setUpgradeReason] = useState("");
  const [uninstallProtection, setUninstallProtection] = useState<AgentUninstallProtectionStatus | null>(null);
  const [uninstallLoading, setUninstallLoading] = useState(true);
  const [uninstallBusy, setUninstallBusy] = useState(false);
  const [uninstallModal, setUninstallModal] = useState(false);
  const [uninstallMessage, setUninstallMessage] = useState("");
  const [uninstallMessageIsError, setUninstallMessageIsError] = useState(false);
  const [uninstallLoadFailed, setUninstallLoadFailed] = useState(false);
  const [uninstallLoadError, setUninstallLoadError] = useState("");

  const loadUpgradeStatus = useCallback(async (quiet = false) => {
    if (!quiet) setUpgradeLoading(true);
    try {
      const response = await fetch("/api/v1/agent-upgrades/status", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(agentManagementError(data, "Không thể đọc trạng thái cập nhật Agent"));
      const next: AgentUpgradeStatus = {
        targetVersion: String(data.targetVersion ?? ""),
        minimumSelfUpdateVersion: String(data.minimumSelfUpdateVersion ?? ""),
        artifacts: data.artifacts,
        items: Array.isArray(data.items) ? data.items : [],
      };
      setUpgradeStatus(next);
      setSelectedUpgradeServerIds((current) => current.filter((serverId) => next.items.some((item) => item.serverId === serverId && agentUpgradeCanSelect(item))));
      setUpgradeMessageIsError(false);
    } catch (reason) {
      setUpgradeMessageIsError(true);
      setUpgradeMessage(reason instanceof Error ? reason.message : "Không thể đọc trạng thái cập nhật Agent");
    } finally {
      if (!quiet) setUpgradeLoading(false);
    }
  }, [token]);

  const loadUninstallProtection = useCallback(async (quiet = false) => {
    if (!quiet) setUninstallLoading(true);
    try {
      const response = await fetch("/api/v1/settings/agent-uninstall-protection", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(agentManagementError(data, "Không thể đọc bảo vệ gỡ cài đặt Agent"));
      setUninstallProtection({
        configured: data.configured === true,
        revision: Number(data.revision ?? 0),
        updatedAt: data.updatedAt ? String(data.updatedAt) : null,
        totalAgents: Number(data.totalAgents ?? 0),
        appliedAgents: Number(data.appliedAgents ?? 0),
        pendingAgents: Number(data.pendingAgents ?? 0),
        failedAgents: Number(data.failedAgents ?? 0),
        manualRequiredAgents: Number(data.manualRequiredAgents ?? 0),
      });
      setUninstallLoadFailed(false);
      setUninstallLoadError("");
      setUninstallMessageIsError(false);
    } catch (reason) {
      setUninstallLoadFailed(true);
      setUninstallLoadError(reason instanceof Error ? reason.message : "Không thể đọc bảo vệ gỡ cài đặt Agent");
    } finally {
      if (!quiet) setUninstallLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetch("/api/v1/agent-packages/status", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail ?? "Không thể đọc cấu hình bộ cài");
        return data;
      })
      .then(setStatus)
      .catch((reason) => {
        setMessageIsError(true);
        setMessage(reason instanceof Error ? reason.message : "Không thể đọc cấu hình bộ cài");
      });
  }, [token]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadUpgradeStatus();
      if (canManageUninstallProtection) void loadUninstallProtection();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [canManageUninstallProtection, loadUpgradeStatus, loadUninstallProtection]);

  const upgradeHasActiveJobs = Boolean(upgradeStatus?.items.some(agentUpgradeIsActive));
  useEffect(() => {
    if (!upgradeHasActiveJobs) return;
    const timer = window.setInterval(() => void loadUpgradeStatus(true), 3_000);
    return () => window.clearInterval(timer);
  }, [loadUpgradeStatus, upgradeHasActiveJobs]);

  const uninstallRolloutPending = Boolean(!uninstallLoadFailed && uninstallProtection?.configured && uninstallProtection.pendingAgents > 0);
  useEffect(() => {
    if (!uninstallRolloutPending) return;
    const timer = window.setInterval(() => void loadUninstallProtection(true), 5_000);
    return () => window.clearInterval(timer);
  }, [loadUninstallProtection, uninstallRolloutPending]);

  const visibleUpgradeItems = useMemo(() => {
    const query = normalizeSearchText(upgradeSearch);
    return (upgradeStatus?.items ?? []).filter((item) => {
      const state = agentUpgradeState(item);
      return (upgradeOsFilter === "all" || item.osFamily === upgradeOsFilter) &&
        (upgradeStateFilter === "all" || state === upgradeStateFilter) &&
        (!query || normalizeSearchText(`${item.serverName} ${item.architecture} ${item.currentVersion} ${item.targetVersion} ${item.reason}`).includes(query));
    });
  }, [upgradeOsFilter, upgradeSearch, upgradeStateFilter, upgradeStatus]);
  const visibleSelectableUpgradeItems = visibleUpgradeItems.filter(agentUpgradeCanSelect);
  const selectedUpgradeItems = (upgradeStatus?.items ?? []).filter((item) => selectedUpgradeServerIds.includes(item.serverId) && agentUpgradeCanSelect(item));
  const allVisibleUpgradeItemsSelected = visibleSelectableUpgradeItems.length > 0 && visibleSelectableUpgradeItems.every((item) => selectedUpgradeServerIds.includes(item.serverId));

  function toggleVisibleUpgradeItems() {
    const visibleIds = visibleSelectableUpgradeItems.map((item) => item.serverId);
    setSelectedUpgradeServerIds((current) => allVisibleUpgradeItemsSelected
      ? current.filter((serverId) => !visibleIds.includes(serverId))
      : [...new Set([...current, ...visibleIds])].slice(0, 100));
  }

  async function submitAgentUpgrade(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const reason = upgradeReason.trim();
    if (selectedUpgradeItems.length === 0 || selectedUpgradeItems.length > 100 || reason.length < 5) return;
    setUpgradeBusy(true);
    setUpgradeMessage("");
    setUpgradeMessageIsError(false);
    try {
      const response = await fetch("/api/v1/agent-upgrades", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          server_ids: selectedUpgradeItems.map((item) => item.serverId),
          reason,
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(agentManagementError(data, "Không thể tạo tác vụ cập nhật Agent"));
      const queued = Array.isArray(data.queued) ? data.queued as Array<{ serverId?: unknown }> : [];
      const skipped = Array.isArray(data.skipped) ? data.skipped as Array<{ serverId?: unknown }> : [];
      const queuedIds = new Set(queued.map((item) => String(item.serverId ?? "")).filter(Boolean));
      const queuedCount = queued.length || selectedUpgradeItems.length;
      const skippedCount = skipped.length;
      setUpgradeMessage(skippedCount > 0
        ? `Đã xếp hàng cập nhật ${queuedCount} Agent; ${skippedCount} Agent bị bỏ qua và vẫn được giữ chọn để bạn kiểm tra.`
        : `Đã xếp hàng cập nhật ${queuedCount} Agent. Trạng thái sẽ tự làm mới tại đây.`);
      setSelectedUpgradeServerIds((current) => current.filter((serverId) => !queuedIds.has(serverId)));
      setUpgradeReason("");
      setUpgradeModal(false);
      await loadUpgradeStatus(true);
    } catch (reasonValue) {
      setUpgradeMessageIsError(true);
      setUpgradeMessage(reasonValue instanceof Error ? reasonValue.message : "Không thể tạo tác vụ cập nhật Agent");
    } finally {
      setUpgradeBusy(false);
    }
  }

  async function saveUninstallProtection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const newPassword = String(form.get("new_password") ?? "");
    const confirmPassword = String(form.get("confirm_password") ?? "");
    if (newPassword !== confirmPassword) {
      setUninstallMessageIsError(true);
      setUninstallMessage("Hai lần nhập mật khẩu gỡ Agent không khớp.");
      return;
    }
    setUninstallBusy(true);
    setUninstallMessage("");
    setUninstallMessageIsError(false);
    try {
      const response = await fetch("/api/v1/settings/agent-uninstall-protection", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          current_password: uninstallProtection?.configured ? String(form.get("current_password") ?? "") : "",
          new_password: newPassword,
          confirm_password: confirmPassword,
          reason: form.get("reason"),
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(agentManagementError(data, "Không thể lưu mật khẩu bảo vệ gỡ Agent"));
      formElement.reset();
      setUninstallModal(false);
      setUninstallMessage(uninstallProtection?.configured
        ? "Đã đổi mật khẩu gỡ Agent. Các máy trực tuyến sẽ nhận revision mới ở lần đồng bộ kế tiếp."
        : "Đã thiết lập mật khẩu gỡ Agent. Theo dõi trạng thái áp dụng ở bảng bên dưới.");
      await loadUninstallProtection();
    } catch (reasonValue) {
      setUninstallMessageIsError(true);
      setUninstallMessage(reasonValue instanceof Error ? reasonValue.message : "Không thể lưu mật khẩu bảo vệ gỡ Agent");
    } finally {
      setUninstallBusy(false);
    }
  }

  async function saveDashboardUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setMessage("");
    setMessageIsError(false);
    const response = await fetch("/api/v1/settings/dashboard-url", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        dashboard_url: form.get("dashboard_url"),
        confirm_existing_agents: form.get("confirm_existing_agents") === "on",
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      setMessageIsError(true);
      setMessage(data.detail ?? "Không thể cập nhật địa chỉ hệ thống");
      return;
    }
    setStatus((current) => current ? { ...current, dashboardUrl: data.dashboardUrl } : current);
    setMessageIsError(false);
    setMessage(
      data.existingAgentsNeedMigration
        ? "Đã đổi URL. Bộ cài mới dùng domain mới; agent cũ cần kế hoạch migrate endpoint/CA."
        : "Đã khóa URL HTTPS dùng để sinh bộ cài Agent.",
    );
  }

  async function downloadPackage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    const osFamily = submitter?.dataset.os as OSFamily | undefined;
    if (!osFamily || !["linux", "windows"].includes(osFamily)) return;
    const form = new FormData(event.currentTarget);
    setBusy(osFamily);
    setMessage("");
    setMessageIsError(false);
    try {
      const response = await fetch("/api/v1/agent-packages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          label: form.get("label"),
          os_family: osFamily,
          linux_profile: osFamily === "linux" ? linuxProfile : null,
          expires_minutes: Number(form.get("expires_minutes")),
        }),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail ?? "Không thể tạo bộ cài Agent");
      }
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const filename = disposition.match(/filename="([^"]+)"/)?.[1] ??
        (osFamily === "windows" ? "TramAgent.msi" : "TramAgent-Linux.run");
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setMessage(
        osFamily === "windows"
          ? "Đã tạo MSI dùng một lần. Giữ nguyên tên file, chép sang đúng Windows Server và chạy bằng Administrator."
          : `Đã tạo gói offline ${LINUX_OFFLINE_PROFILE_LABELS[linuxProfile]} dùng một lần. Máy đích không cần kết nối Internet hoặc repository khi cài. Chạy: chmod +x <file>.run && sudo ./<file>.run`,
      );
      setMessageIsError(false);
    } catch (reason) {
      setMessageIsError(true);
      setMessage(reason instanceof Error ? reason.message : "Không thể tạo bộ cài Agent");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="agent-package-layout">
      <article className="panel agent-package-intro">
        <p className="eyebrow">ZERO-TOUCH ENROLLMENT</p>
        <h2>Bộ cài tự nhận đúng Operation Portal</h2>
        <p>
          Domain và chế độ xác minh kết nối được lấy từ cấu hình HTTPS của hệ thống.
          Thông tin nhận diện riêng chỉ được sinh trên máy đích, không nằm trong file tải về.
        </p>
        <form className="package-origin" key={status?.dashboardUrl} onSubmit={saveDashboardUrl}>
          <span>URL Operation Portal dùng để sinh Agent</span>
          <input
            name="dashboard_url"
            type="url"
            required
            defaultValue={status?.dashboardUrl ?? ""}
            placeholder={typeof window === "undefined" ? "https://ops.company.com" : window.location.origin}
          />
          <label className="package-confirm">
            <input name="confirm_existing_agents" type="checkbox" />
            Tôi hiểu agent cũ vẫn giữ endpoint cũ nếu đổi domain
          </label>
          <button className="button ghost" type="submit">Lưu URL HTTPS</button>
          <small>Hãy mở Operation Portal bằng chính domain mới và kiểm tra kết nối HTTPS trước khi lưu.</small>
        </form>
        <ul>
          <li>Claim hết hạn sau tối đa 60 phút và chỉ dùng được một lần.</li>
          <li>
            Kết nối cài đặt: {status?.webTlsTrust === "system" ? "chứng thư công khai" : "chứng thư nội bộ đã xác minh"};
            kênh quản trị Agent sử dụng chứng thư riêng.
          </li>
          <li>Windows MSI cài service LocalSystem, tự khởi động cùng Windows và tự restart khi lỗi.</li>
          <li>Linux không cần Internet hay repository khi cài. File .run mang sẵn bộ công cụ Disk/LVM đúng Ubuntu 22.04/24.04 hoặc Oracle Linux 7/8 đã chọn, kiểm tra hash trước khi cài cục bộ.</li>
          <li>Windows/Linux vẫn tự xuất hiện đúng mục theo inventory thực tế.</li>
        </ul>
      </article>

      <form
        className="panel agent-package-form"
        onSubmit={downloadPackage}
      >
        <div className="panel-head">
          <div>
            <h2>Tạo bộ cài riêng cho máy chủ</h2>
            <p>Agent {status?.agentVersion ?? "…"} · chỉ quản trị viên được tạo gói cài một lần.</p>
          </div>
        </div>
        <label>
          Tên gợi nhớ / ticket
          <input name="label" required minLength={3} maxLength={120} placeholder="SRV-PROD-01 hoặc CHG-1234" />
        </label>
        <label>
          Thời hạn cài đặt
          <select name="expires_minutes" defaultValue="30">
            <option value="15">15 phút</option>
            <option value="30">30 phút</option>
            <option value="60">60 phút</option>
          </select>
        </label>
        <label>
          Hệ điều hành của máy Linux
          <select value={linuxProfile} onChange={(event) => setLinuxProfile(event.target.value as LinuxOfflineProfile)}>
            {(Object.entries(LINUX_OFFLINE_PROFILE_LABELS) as Array<[LinuxOfflineProfile, string]>).map(([profile, label]) => (
              <option key={profile} value={profile} disabled={status?.linuxOfflineProfiles?.[profile] === false}>
                {label}{status?.linuxOfflineProfiles?.[profile] === false ? " · chưa có pack" : ""}
              </option>
            ))}
          </select>
          <small>Phải chọn đúng OS/version của máy đích. Bộ cài sẽ từ chối trước khi thay Agent nếu không khớp.</small>
        </label>
        <div className="agent-package-options">
          <button
            className="package-option linux"
            type="submit"
            data-os="linux"
            disabled={busy !== null || status?.linuxAvailable === false || status?.linuxOfflineProfiles?.[linuxProfile] === false || status?.agentTlsCaAvailable === false}
          >
            <span>L</span>
            <b>Tải Linux .run</b>
            <small>{LINUX_OFFLINE_PROFILE_LABELS[linuxProfile]} · x86_64 · cài không cần repository</small>
          </button>
          <button
            className="package-option windows"
            type="submit"
            data-os="windows"
            disabled={busy !== null || status?.windowsMsiAvailable === false || status?.agentTlsCaAvailable === false}
          >
            <span>W</span>
            <b>Tải Windows .msi</b>
            <small>Windows Server 2025 · auto-start service</small>
          </button>
        </div>
        {busy && <p className="package-progress">Đang chuẩn bị gói cài {busy}…</p>}
        {status && status.linuxAvailable && status.linuxOfflineProfiles?.[linuxProfile] === false && (
          <p className="package-warning">Pack offline cho {LINUX_OFFLINE_PROFILE_LABELS[linuxProfile]} chưa sẵn sàng trên máy triển khai.</p>
        )}
        {status && !status.windowsMsiAvailable && (
          <p className="package-warning">Bộ cài Windows chưa sẵn sàng. Hãy liên hệ quản trị viên triển khai.</p>
        )}
        {status && !status.linuxAvailable && (
          <p className="package-warning">Bộ cài Linux chưa sẵn sàng. Hãy liên hệ quản trị viên triển khai.</p>
        )}
        {status && !status.agentTlsCaAvailable && (
          <p className="package-warning">
            Kênh bảo mật dành cho Agent chưa sẵn sàng. Hãy liên hệ quản trị viên triển khai.
          </p>
        )}
        {message && <p className={`settings-message${messageIsError ? " error" : ""}`}>{message}</p>}
        <div className="package-security-note">
          Không đổi tên MSI Windows: tên file chứa locator và chế độ xác minh TLS. Không gửi bộ cài qua kênh công cộng và không tái sử dụng file sau khi một máy đã claim.
        </div>
      </form>

      <article className="panel agent-fleet-panel">
        <div className="agent-management-head">
          <div>
            <p className="eyebrow">FLEET UPDATE</p>
            <h2>Cập nhật Agent trực tiếp</h2>
            <p>
              Bản phát hành hiện tại <b>v{upgradeStatus?.targetVersion || "…"}</b>
              {upgradeStatus?.minimumSelfUpdateVersion ? ` · tự cập nhật từ v${upgradeStatus.minimumSelfUpdateVersion}` : ""}.
              Máy quá cũ phải nâng thủ công một lần trước khi nhận cập nhật từ website.
            </p>
          </div>
          <div className="agent-management-actions">
            <button type="button" className="button ghost" disabled={upgradeLoading || upgradeBusy} onClick={() => void loadUpgradeStatus()}>
              {upgradeLoading ? "Đang đọc…" : "↻ Làm mới"}
            </button>
            <button type="button" className="button primary" disabled={upgradeBusy || selectedUpgradeItems.length === 0} onClick={() => { setUpgradeReason(""); setUpgradeModal(true); }}>
              Cập nhật đã chọn ({selectedUpgradeItems.length})
            </button>
          </div>
        </div>
        <div className="agent-upgrade-summary">
          <span><b>{upgradeStatus?.items.length ?? 0}</b><small>Tổng Agent</small></span>
          <span><b>{upgradeStatus?.items.filter((item) => ["eligible", "update_available"].includes(agentUpgradeState(item))).length ?? 0}</b><small>Có bản mới</small></span>
          <span><b>{upgradeStatus?.items.filter(agentUpgradeIsActive).length ?? 0}</b><small>Đang cập nhật</small></span>
          <span><b>{upgradeStatus?.items.filter((item) => agentUpgradeState(item) === "manual_required").length ?? 0}</b><small>Cần nâng thủ công</small></span>
        </div>
        <div className="agent-upgrade-filters" aria-label="Tìm kiếm và lọc Agent">
          <input type="search" value={upgradeSearch} onChange={(event) => setUpgradeSearch(event.target.value)} placeholder="Tìm hostname, kiến trúc hoặc phiên bản…" aria-label="Tìm Agent cần cập nhật" />
          <select value={upgradeOsFilter} onChange={(event) => setUpgradeOsFilter(event.target.value as "all" | OSFamily)} aria-label="Lọc Agent theo hệ điều hành">
            <option value="all">Mọi hệ điều hành</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
          </select>
          <select value={upgradeStateFilter} onChange={(event) => setUpgradeStateFilter(event.target.value)} aria-label="Lọc Agent theo trạng thái cập nhật">
            <option value="all">Mọi trạng thái</option>
            <option value="eligible">Có bản mới</option>
            <option value="current">Mới nhất</option>
            <option value="newer">Mới hơn bản phát hành</option>
            <option value="manual_required">Cần nâng thủ công</option>
            <option value="offline">Mất kết nối</option>
            <option value="unsupported">Không hỗ trợ</option>
            <option value="queued">Đang chờ Agent</option>
            <option value="dispatched">Đang tải gói</option>
            <option value="installing">Đang cài đặt</option>
            <option value="failed">Cập nhật thất bại</option>
          </select>
        </div>
        <div className="resource-table-scroll agent-upgrade-table-wrap">
          <table className="resource-table agent-upgrade-table">
            <thead><tr>
              <th className="check-column"><input type="checkbox" aria-label="Chọn tất cả Agent có thể cập nhật đang hiển thị" checked={allVisibleUpgradeItemsSelected} disabled={!visibleSelectableUpgradeItems.length} onChange={toggleVisibleUpgradeItems} /></th>
              <th>Máy chủ</th><th>Hệ điều hành</th><th>Phiên bản</th><th>Trạng thái</th><th>Chi tiết</th>
            </tr></thead>
            <tbody>
              {visibleUpgradeItems.map((item) => {
                const state = agentUpgradeState(item);
                const canSelect = agentUpgradeCanSelect(item);
                const targetVersion = item.targetVersion || upgradeStatus?.targetVersion || "—";
                return <tr key={item.serverId}>
                  <td><input type="checkbox" aria-label={`Chọn cập nhật Agent trên ${item.serverName}`} checked={selectedUpgradeServerIds.includes(item.serverId)} disabled={!canSelect || (!selectedUpgradeServerIds.includes(item.serverId) && selectedUpgradeServerIds.length >= 100)} onChange={() => setSelectedUpgradeServerIds((current) => current.includes(item.serverId) ? current.filter((serverId) => serverId !== item.serverId) : [...current, item.serverId].slice(0, 100))} /></td>
                  <td><b>{item.serverName}</b><small>{item.architecture || "Không rõ kiến trúc"}</small></td>
                  <td><span className={`os-family-badge ${item.osFamily}`}>{item.osFamily === "windows" ? "Windows" : "Linux"}</span></td>
                  <td><b>v{item.currentVersion || "—"}</b><small>{["current", "newer"].includes(state) ? "Không hạ phiên bản" : `Mục tiêu v${targetVersion}`}</small></td>
                  <td><span className={`state-pill agent-upgrade-state ${state}`}>{agentUpgradeStateLabels[state] ?? state}</span>{item.activeJobId ? <small>Job {item.activeJobId.slice(0, 8)}</small> : null}</td>
                  <td><span className="agent-upgrade-reason">{item.reason || (canSelect ? "Sẵn sàng nhận gói đã xác minh" : "Backend chưa cho phép cập nhật")}</span></td>
                </tr>;
              })}
            </tbody>
          </table>
          {!upgradeLoading && visibleUpgradeItems.length === 0 && <div className="empty-state">Không có Agent khớp điều kiện tìm kiếm và bộ lọc.</div>}
          {upgradeLoading && <div className="empty-state">Đang đọc trạng thái phiên bản từ hệ thống…</div>}
        </div>
        <div className="package-security-note">Mỗi lượt chọn tối đa 100 Agent. Website chỉ gửi ID máy chủ và lý do. Backend tự chọn đúng artifact theo hệ điều hành/kiến trúc, khóa phiên bản đích và từ chối downgrade; trình duyệt không được chỉ định URL tải, hash hoặc version.</div>
        {upgradeMessage && <p className={`settings-message${upgradeMessageIsError ? " error" : ""}`}>{upgradeMessage}</p>}
      </article>

      {canManageUninstallProtection && <article className="panel agent-uninstall-panel">
        <div className="agent-management-head">
          <div>
            <p className="eyebrow">TAMPER PROTECTION</p>
            <h2>Bảo vệ gỡ cài đặt Agent</h2>
            <p>Một mật khẩu gỡ Agent dùng chung cho toàn fleet. Mật khẩu không được hiển thị lại, không trả về trình duyệt và không ghi vào nhật ký.</p>
          </div>
          <div className="agent-management-actions">
            <span className={`state-pill ${uninstallLoadFailed ? "danger" : uninstallProtection?.configured ? "success" : "warning"}`}>{uninstallLoading ? "Đang đọc…" : uninstallLoadFailed ? "Không tải được chính sách" : uninstallProtection?.configured ? `Đã bật · revision ${uninstallProtection.revision}` : "Chưa thiết lập"}</span>
            {uninstallLoadFailed
              ? <button type="button" className="button ghost" disabled={uninstallLoading || uninstallBusy} onClick={() => void loadUninstallProtection()}>{uninstallLoading ? "Đang thử lại…" : "Thử lại"}</button>
              : <button type="button" className="button primary" disabled={uninstallLoading || uninstallBusy} onClick={() => setUninstallModal(true)}>{uninstallProtection?.configured ? "Đổi mật khẩu" : "Thiết lập mật khẩu"}</button>}
          </div>
        </div>
        <div className="agent-protection-rollout">
          <span><b>{uninstallProtection?.appliedAgents ?? 0}</b><small>Đã áp dụng</small></span>
          <span><b>{uninstallProtection?.pendingAgents ?? 0}</b><small>Chờ đồng bộ</small></span>
          <span><b>{uninstallProtection?.failedAgents ?? 0}</b><small>Cần xử lý lỗi</small></span>
          <span><b>{uninstallProtection?.manualRequiredAgents ?? 0}</b><small>Agent cũ cần nâng thủ công</small></span>
          <span><b>{uninstallProtection?.totalAgents ?? 0}</b><small>Tổng Agent</small></span>
        </div>
        {(uninstallProtection?.failedAgents ?? 0) > 0 && <div className="resource-help warning">Một số Agent đã thử đồng bộ policy 3 lần nhưng vẫn lỗi. Hệ thống đã dừng retry tự động để tránh tạo job liên tục; kiểm tra dung lượng/quyền ACL của máy đích rồi lưu lại policy để tạo revision mới.</div>}
        <div className="resource-help warning">
          Bảo vệ này khóa quy trình uninstall được hỗ trợ và yêu cầu đúng mật khẩu tại máy đích. Người đã có quyền <b>root</b> trên Linux hoặc <b>Local Administrator</b> trên Windows vẫn có thể phá hoặc thay file dịch vụ bằng quyền hệ điều hành; hãy kết hợp RBAC, MFA và kiểm soát đặc quyền endpoint.
        </div>
        {uninstallProtection?.configured && uninstallProtection.updatedAt && <p className="agent-protection-updated">Cập nhật gần nhất {new Date(uninstallProtection.updatedAt).toLocaleString("vi-VN")} · revision {uninstallProtection.revision}. Agent cũ chỉ được bảo vệ sau khi nhận policy tương thích.</p>}
        {uninstallLoadError && <p className="settings-message error">{uninstallLoadError}</p>}
        {uninstallMessage && <p className={`settings-message${uninstallMessageIsError ? " error" : ""}`}>{uninstallMessage}</p>}
      </article>}

      {upgradeModal && <ModalShell title={`Cập nhật ${selectedUpgradeItems.length} Agent`} subtitle={`Backend khóa mục tiêu v${upgradeStatus?.targetVersion || "mới nhất"}; dịch vụ Agent sẽ khởi động lại trong thời gian ngắn`} close={() => { if (!upgradeBusy) setUpgradeModal(false); }}>
        <form className="resource-form" onSubmit={submitAgentUpgrade}>
          <div className="agent-upgrade-confirm-list">{selectedUpgradeItems.map((item) => <div key={item.serverId}><b>{item.serverName}</b><span>{item.osFamily === "windows" ? "Windows" : "Linux"} · v{item.currentVersion} → v{item.targetVersion || upgradeStatus?.targetVersion}</span></div>)}</div>
          <label>Lý do / ticket<textarea value={upgradeReason} onChange={(event) => setUpgradeReason(event.target.value)} minLength={5} maxLength={500} rows={3} required placeholder="CHG-1234 · Nâng Agent để nhận bản vá và chính sách mới" /></label>
          <div className="resource-help">Agent tải artifact do backend chọn qua kênh xác thực, kiểm tra hash/chữ ký rồi mới cài. Trạng thái chỉ hoàn tất sau khi Agent mới khởi động và báo đúng phiên bản.</div>
          <div className="modal-actions"><button type="button" className="button ghost" disabled={upgradeBusy} onClick={() => setUpgradeModal(false)}>Hủy</button><button className="button primary" disabled={upgradeBusy || upgradeReason.trim().length < 5}>{upgradeBusy ? "Đang xếp hàng…" : "Bắt đầu cập nhật"}</button></div>
        </form>
      </ModalShell>}

      {uninstallModal && !uninstallLoadFailed && <ModalShell title={uninstallProtection?.configured ? "Đổi mật khẩu gỡ Agent" : "Thiết lập mật khẩu gỡ Agent"} subtitle="Mật khẩu riêng của fleet, không phải mật khẩu đăng nhập website" close={() => { if (!uninstallBusy) setUninstallModal(false); }}>
        <form className="resource-form" onSubmit={saveUninstallProtection}>
          {uninstallProtection?.configured && <label>Mật khẩu gỡ Agent hiện tại<input name="current_password" type="password" autoComplete="off" minLength={1} maxLength={1024} required /></label>}
          <label>Mật khẩu gỡ Agent mới<input name="new_password" type="password" autoComplete="off" minLength={14} maxLength={1024} required /></label>
          <label>Nhập lại mật khẩu mới<input name="confirm_password" type="password" autoComplete="off" minLength={14} maxLength={1024} required /></label>
          <label>Lý do / ticket<textarea name="reason" minLength={5} maxLength={500} rows={3} required placeholder="SEC-1234 · Bật hoặc luân phiên mật khẩu chống gỡ Agent" /></label>
          <label className="check"><input name="acknowledge" type="checkbox" required /> Tôi hiểu mật khẩu không thể xem lại và Agent cũ chưa nhận policy vẫn chưa được bảo vệ.</label>
          <div className="danger-panel">Hãy lưu mật khẩu trong kho bí mật của doanh nghiệp. Không gửi qua email/chat và không dùng chung với mật khẩu đăng nhập Local hoặc Domain.</div>
          <div className="modal-actions"><button type="button" className="button ghost" disabled={uninstallBusy} onClick={() => setUninstallModal(false)}>Hủy</button><button className="button primary" disabled={uninstallBusy}>{uninstallBusy ? "Đang lưu…" : uninstallProtection?.configured ? "Đổi mật khẩu" : "Bật bảo vệ gỡ cài đặt"}</button></div>
        </form>
      </ModalShell>}
    </section>
  );
}

type PlatformUserRow = { id: string; username: string; displayName: string; role: string; source: "local" | "ldap"; enabled: boolean; mfaEnrolled: boolean; createdAt: string; groupIds: string[] };
type PlatformRoleRow = { name: string; displayName: string; description: string; permissions: string[]; system: boolean };
type PermissionRow = { id: string; group: string; label: string; description: string };

function AccessView({ token, currentUser }: { token: string; currentUser: CurrentUser }) {
  const [users, setUsers] = useState<PlatformUserRow[]>([]);
  const [roles, setRoles] = useState<PlatformRoleRow[]>([]);
  const [groups, setGroups] = useState<PlatformGroupRow[]>([]);
  const [permissions, setPermissions] = useState<PermissionRow[]>([]);
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [editingUser, setEditingUser] = useState<PlatformUserRow | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showLdap, setShowLdap] = useState(false);
  const [showRoles, setShowRoles] = useState(false);
  const [showGroups, setShowGroups] = useState(false);
  const [groupEditor, setGroupEditor] = useState<string | null>(null);
  const [roleEditor, setRoleEditor] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [messageError, setMessageError] = useState(false);
  const [ldap, setLdap] = useState<Record<string, unknown>>({ enabled: false, port: 636, use_ssl: true, user_attribute: "sAMAccountName", display_attribute: "displayName", domain_label: "DOMAIN", default_role: "viewer", allowed_group_dns: [] });
  const [ldapDirectoryGroups, setLdapDirectoryGroups] = useState<Array<{ dn: string; name: string }>>([]);
  const selectedRole = roles.find((role) => role.name === roleEditor) ?? null;
  const selectedGroup = groups.find((group) => group.id === groupEditor) ?? null;
  const ldapAllowedGroupDns = Array.isArray(ldap.allowed_group_dns) ? ldap.allowed_group_dns.map(String) : [];
  const ldapGroupOptionMap = new Map(ldapDirectoryGroups.map((group) => [group.dn, group.name]));
  for (const dn of ldapAllowedGroupDns) if (!ldapGroupOptionMap.has(dn)) ldapGroupOptionMap.set(dn, dn);
  const ldapGroupOptions = Array.from(ldapGroupOptionMap, ([dn, name]) => ({ dn, name }));
  const groupedPermissions = useMemo(() => permissions.reduce<Record<string, PermissionRow[]>>((groups, permission) => ({ ...groups, [permission.group]: [...(groups[permission.group] ?? []), permission] }), {}), [permissions]);
  const loadAccess = useCallback(async () => {
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [usersResponse, rolesResponse, groupsResponse, ldapResponse] = await Promise.all([
        fetch("/api/v1/users", { headers }),
        fetch("/api/v1/roles", { headers }),
        fetch("/api/v1/platform-groups", { headers }),
        fetch("/api/v1/settings/ldap", { headers }),
      ]);
      const denied = usersResponse.status === 403;
      setForbidden(denied);
      if (usersResponse.ok) setUsers((await usersResponse.json()).items ?? []);
      else setUsers([]);
      if (rolesResponse.ok) {
        const data = await rolesResponse.json();
        setRoles(data.items ?? []);
        setPermissions(data.permissionCatalog ?? []);
      } else {
        setRoles([]);
        setPermissions([]);
      }
      if (groupsResponse.ok) setGroups((await groupsResponse.json()).items ?? []);
      else setGroups([]);
      if (ldapResponse.ok) {
        const ldapData = await ldapResponse.json();
        setLdap((current) => ({ ...current, ...ldapData }));
      }
    } catch {
      setMessage("Không thể tải danh sách người dùng và role. Hãy kiểm tra kết nối rồi thử lại.");
      setMessageError(true);
    }
  }, [token]);
  useEffect(() => {
    const timer = window.setTimeout(() => void loadAccess(), 0);
    return () => window.clearTimeout(timer);
  }, [loadAccess]);
  function showResult(text: string, error = false) { setMessage(text); setMessageError(error); }
  async function createLocalUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/v1/users", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ username: form.get("username"), display_name: form.get("display_name"), password: form.get("password"), role: form.get("role") }) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) { showResult("Đã tạo tài khoản Local; MFA sẽ bắt buộc ở lần đăng nhập đầu tiên."); setShowCreate(false); await loadAccess(); }
    else showResult(data.detail ?? "Không thể tạo tài khoản Local", true);
    setBusy(false);
  }
  async function updateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!editingUser) return; setBusy(true);
    const form = new FormData(event.currentTarget); const password = String(form.get("password") ?? "");
    const payload: Record<string, unknown> = { display_name: form.get("display_name"), role: form.get("role"), enabled: form.get("enabled") === "on" };
    if (password) payload.password = password;
    const response = await fetch(`/api/v1/users/${editingUser.id}`, { method: "PATCH", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    const profileUnchanged = response.status === 422 && data.detail === "Không có thay đổi hợp lệ";
    const groupResponse = await fetch(`/api/v1/users/${editingUser.id}/groups`, { method: "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ member_ids: form.getAll("platform_groups") }) });
    const groupData = await groupResponse.json().catch(() => ({}));
    if ((response.ok || profileUnchanged) && groupResponse.ok) { showResult(editingUser.source === "ldap" ? "Đã cập nhật role/trạng thái/group của user LDAP." : "Đã cập nhật tài khoản Local và group."); setEditingUser(null); await loadAccess(); }
    else showResult((!response.ok && !profileUnchanged ? data.detail : groupData.detail) ?? "Không thể cập nhật tài khoản", true);
    setBusy(false);
  }
  async function deleteUsers() {
    if (!selectedUserIds.length || !window.confirm(`Xóa ${selectedUserIds.length} tài khoản khỏi website? User LDAP chỉ bị xóa mapping local, không bị xóa trong Active Directory.`)) return;
    setBusy(true);
    const response = await fetch("/api/v1/users", { method: "DELETE", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ user_ids: selectedUserIds }) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) { showResult(`Đã xóa ${String(data.deleted ?? selectedUserIds.length)} tài khoản.`); setSelectedUserIds([]); await loadAccess(); }
    else showResult(data.detail ?? "Không thể xóa tài khoản", true);
    setBusy(false);
  }
  async function saveLdap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); const form = new FormData(event.currentTarget);
    const payload = { enabled: form.get("enabled") === "on", host: form.get("host"), port: Number(form.get("port")), use_ssl: true, base_dn: form.get("base_dn"), bind_dn: form.get("bind_dn"), bind_password: form.get("bind_password"), ca_certificate: form.get("ca_certificate"), user_attribute: form.get("user_attribute"), display_attribute: form.get("display_attribute"), domain_label: form.get("domain_label"), default_role: form.get("default_role"), allowed_group_dns: form.getAll("allowed_group_dns") };
    const response = await fetch("/api/v1/settings/ldap", { method: "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) {
      const { userSync, ...savedConfig } = data;
      setLdap((current) => ({ ...current, ...savedConfig }));
      showResult(userSync ? `Đã lưu LDAP và đồng bộ ${String(userSync.scanned ?? 0)} user AD (${String(userSync.created ?? 0)} mới, ${String(userSync.updated ?? 0)} cập nhật).` : "Đã lưu cấu hình LDAP.");
      setShowLdap(false);
      await loadAccess();
    }
    else showResult(data.detail ?? "Không thể lưu LDAP", true);
    setBusy(false);
  }
  async function resetUserMfa(user: PlatformUserRow) {
    if (!window.confirm(`Reset MFA của ${user.displayName || user.username}? Lần đăng nhập sau người dùng phải quét QR mới.`)) return;
    setBusy(true);
    const response = await fetch(`/api/v1/users/${user.id}/mfa`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json().catch(() => ({}));
    if (response.ok) {
      showResult(`Đã reset MFA của ${user.displayName || user.username}. Lần đăng nhập sau sẽ hiển thị QR mới.`);
      setEditingUser(null);
      await loadAccess();
    } else showResult(data.detail ?? "Không thể reset MFA", true);
    setBusy(false);
  }
  async function scanLdapDirectoryGroups() {
    setBusy(true);
    const response = await fetch("/api/v1/settings/ldap/groups", { headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json().catch(() => ({}));
    if (response.ok) { setLdapDirectoryGroups(data.items ?? []); showResult(`Đã quét ${String(data.items?.length ?? 0)} group LDAP.`); }
    else showResult(data.detail ?? "Không thể quét group LDAP", true);
    setBusy(false);
  }
  async function syncLdapDirectoryUsers() {
    setBusy(true);
    const response = await fetch("/api/v1/settings/ldap/users/sync", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json().catch(() => ({}));
    if (response.ok) {
      showResult(`Đã đồng bộ ${String(data.scanned ?? 0)} user AD (${String(data.created ?? 0)} mới, ${String(data.updated ?? 0)} cập nhật, ${String(data.conflicts ?? 0)} trùng tài khoản Local).`);
      await loadAccess();
    } else showResult(data.detail ?? "Không thể đồng bộ user AD", true);
    setBusy(false);
  }
  async function savePlatformGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); const form = new FormData(event.currentTarget); const creating = groupEditor === "__new__";
    const payload = { name: form.get("name"), description: form.get("description"), member_ids: form.getAll("members") };
    const response = await fetch(creating ? "/api/v1/platform-groups" : `/api/v1/platform-groups/${groupEditor}`, { method: creating ? "POST" : "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) { showResult(creating ? "Đã tạo group của trạm vận hành." : "Đã cập nhật group và thành viên."); await loadAccess(); setGroupEditor(String(data.id)); }
    else showResult(data.detail ?? "Không thể lưu group", true);
    setBusy(false);
  }
  async function deletePlatformGroup(group: PlatformGroupRow) {
    if (!window.confirm(`Xóa group ${group.name}? Các share qua group này cũng bị gỡ.`)) return; setBusy(true);
    const response = await fetch(`/api/v1/platform-groups/${group.id}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } }); const data = await response.json().catch(() => ({}));
    if (response.ok) { showResult("Đã xóa group."); setGroupEditor(null); await loadAccess(); } else showResult(data.detail ?? "Không thể xóa group", true);
    setBusy(false);
  }
  async function saveRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); const form = new FormData(event.currentTarget); const creating = roleEditor === "__new__";
    const payload = { name: form.get("name"), display_name: form.get("display_name"), description: form.get("description"), permissions: form.getAll("permissions") };
    const response = await fetch(creating ? "/api/v1/roles" : `/api/v1/roles/${roleEditor}`, { method: creating ? "POST" : "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (response.ok) { showResult(creating ? "Đã tạo role tùy chỉnh." : "Đã lưu quyền của role."); await loadAccess(); setRoleEditor(String(data.name)); }
    else showResult(data.detail ?? "Không thể lưu role", true);
    setBusy(false);
  }
  async function deleteRole(role: PlatformRoleRow) {
    if (role.system || !window.confirm(`Xóa role ${role.displayName}?`)) return; setBusy(true);
    const response = await fetch(`/api/v1/roles/${role.name}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } }); const data = await response.json().catch(() => ({}));
    if (response.ok) { showResult("Đã xóa role."); setRoleEditor(null); await loadAccess(); }
    else showResult(data.detail ?? "Không thể xóa role", true);
    setBusy(false);
  }
  return <section className="panel view-panel access-workspace">
    <div className="panel-head access-head"><div><h2>Người dùng & vai trò</h2><p>Tài khoản Local và AD dùng chung MFA; group dùng để cấp quyền nhìn thấy máy chủ theo đội vận hành.</p></div>{!forbidden && <div className="access-actions"><button className="resource-icon-button" type="button" title="Tạo tài khoản Local" onClick={() => setShowCreate(true)}>+</button><button className="resource-icon-button danger" type="button" title="Xóa tài khoản đã chọn" disabled={!selectedUserIds.length || busy} onClick={() => void deleteUsers()}>−</button><button className="button ghost compact" type="button" disabled={busy || ldap.enabled !== true} onClick={() => void syncLdapDirectoryUsers()}>Đồng bộ AD</button><button className="button ghost compact" type="button" onClick={() => { setGroupEditor(null); setShowGroups(true); }}>Groups</button><button className="button ghost compact" type="button" onClick={() => { setRoleEditor(null); setShowRoles(true); }}>Roles</button><button className="resource-icon-button settings" type="button" title="Cấu hình LDAP" onClick={() => setShowLdap(true)}>⚙</button></div>}</div>
    {message && <p className={`settings-message${messageError ? " error" : ""}`}>{message}</p>}
    <div className="access-table-scroll"><table className="resource-table access-table"><thead><tr><th className="check-column"><input type="checkbox" checked={users.length > 0 && users.every((user) => selectedUserIds.includes(user.id))} onChange={() => setSelectedUserIds(users.every((user) => selectedUserIds.includes(user.id)) ? [] : users.map((user) => user.id))} /></th><th>Người dùng</th><th>Nguồn</th><th>Role</th><th>Trạng thái</th><th /></tr></thead><tbody>{users.map((user) => <tr key={user.id} className="clickable" onClick={() => setEditingUser(user)}><td onClick={(event) => event.stopPropagation()}><input type="checkbox" checked={selectedUserIds.includes(user.id)} onChange={() => setSelectedUserIds((current) => current.includes(user.id) ? current.filter((id) => id !== user.id) : [...current, user.id])} /></td><td><b>{user.displayName || user.username}</b><small>{user.username} · tạo {new Date(user.createdAt).toLocaleDateString("vi-VN")}</small></td><td><span className={`identity-source ${user.source}`} title={user.source === "ldap" ? "Active Directory / LDAP" : "Tài khoản Local"}>{user.source === "ldap" ? "AD" : "Local"}</span></td><td><span className="state-pill">{roles.find((role) => role.name === user.role)?.displayName ?? user.role}</span></td><td><span className={`state-pill ${user.enabled ? "success" : "warning"}`}>{user.enabled ? "Hoạt động" : "Đã khóa"}</span></td><td><button type="button" className="row-more" onClick={(event) => { event.stopPropagation(); setEditingUser(user); }}>Sửa</button></td></tr>)}</tbody></table>{!users.length && <div className="empty-state">{forbidden ? "Role hiện tại không có quyền quản lý người dùng." : "Chưa có người dùng."}</div>}</div>
    <p className="access-note">User AD được đồng bộ từ các group LDAP được phép đăng nhập và có thể gán mọi role hiện có. Đồng bộ lại không ghi đè role riêng; mật khẩu vẫn do Active Directory quản lý.</p>
    {showCreate && <ModalShell title="Tạo tài khoản Local" subtitle="Tài khoản mới bắt buộc thiết lập MFA ở lần đăng nhập đầu tiên" close={() => setShowCreate(false)}><form className="resource-form" onSubmit={createLocalUser}><div className="form-grid"><label>Tên đăng nhập<input name="username" required minLength={3} pattern="[A-Za-z0-9_.@-]+" /></label><label>Role<select name="role" defaultValue="viewer">{roles.map((role) => <option key={role.name} value={role.name}>{role.displayName}</option>)}</select></label></div><label>Tên hiển thị<input name="display_name" required /></label><label>Mật khẩu ban đầu<input name="password" type="password" autoComplete="new-password" required minLength={14} /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setShowCreate(false)}>Hủy</button><button className="button primary" disabled={busy}>Tạo tài khoản</button></div></form></ModalShell>}
    {editingUser && <ModalShell title={`Sửa ${editingUser.username}`} subtitle={editingUser.source === "ldap" ? "User AD: gán bất kỳ role hiện có, trạng thái và group tại website; mật khẩu do Active Directory quản lý" : "Tài khoản Local: đổi thông tin, role, group, trạng thái hoặc đặt mật khẩu mới"} close={() => setEditingUser(null)}><form key={`${editingUser.id}:${editingUser.role}:${editingUser.enabled}:${editingUser.mfaEnrolled}:${editingUser.groupIds?.join(",")}`} className="resource-form" onSubmit={updateUser}><label>Tên hiển thị<input name="display_name" defaultValue={editingUser.displayName} required /></label><label>Role<select name="role" defaultValue={editingUser.role}>{roles.map((role) => <option key={role.name} value={role.name}>{role.displayName}</option>)}</select></label><fieldset><legend>Groups của trạm vận hành</legend><div className="choice-grid">{groups.map((group) => <label key={group.id}><input type="checkbox" name="platform_groups" value={group.id} defaultChecked={editingUser.groupIds?.includes(group.id)} />{group.name}</label>)}</div></fieldset><label className="check"><input type="checkbox" name="enabled" defaultChecked={editingUser.enabled} /> Cho phép đăng nhập</label><label>Mật khẩu mới<input name="password" type="password" minLength={14} autoComplete="new-password" disabled={editingUser.source === "ldap"} placeholder={editingUser.source === "ldap" ? "Đổi tại Active Directory" : "Để trống nếu giữ nguyên"} /></label><div className="mfa-admin-control"><span><b>MFA: {editingUser.mfaEnrolled ? "Đã đăng ký" : "Chờ đăng ký"}</b><small>Reset sẽ hủy khóa TOTP hiện tại; lần đăng nhập sau người dùng phải quét QR mới.</small></span>{currentUser.role === "admin" && <button type="button" className="button danger" disabled={busy} onClick={() => void resetUserMfa(editingUser)}>Reset MFA</button>}</div><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setEditingUser(null)}>Hủy</button><button className="button primary" disabled={busy}>Lưu thay đổi</button></div></form></ModalShell>}
    {showLdap && <ModalShell
      title="Cấu hình LDAP / Active Directory"
      subtitle="Kết nối LDAPS, giới hạn group và đồng bộ thành viên AD vào danh sách người dùng"
      close={() => setShowLdap(false)}
      className="ldap-settings-modal"
      footer={<><button type="button" className="button ghost" onClick={() => setShowLdap(false)}>Hủy</button><button type="submit" form="ldap-settings-form" className="button primary" disabled={busy}>Kiểm tra & lưu LDAP</button></>}
    >
      <form id="ldap-settings-form" key={JSON.stringify(ldap)} className="resource-form ldap-settings-form" onSubmit={saveLdap}>
        <label className="check"><input name="enabled" type="checkbox" defaultChecked={Boolean(ldap.enabled)} /> Bật Domain Login</label>
        <div className="form-grid"><label>LDAP Host<input name="host" defaultValue={String(ldap.host ?? "")} placeholder="dc01.company.local" /></label><label>Cổng<input name="port" type="number" min={1} max={65535} defaultValue={Number(ldap.port ?? 636)} /></label></div>
        <div className="resource-help"><b>LDAPS bắt buộc</b> · Kết nối luôn dùng TLS và xác minh certificate; LDAP plaintext không được phép lưu hoặc sử dụng.</div>
        <label>Base DN<input name="base_dn" defaultValue={String(ldap.base_dn ?? "")} placeholder="DC=company,DC=local" /></label>
        <label>Bind DN<input name="bind_dn" defaultValue={String(ldap.bind_dn ?? "")} placeholder="CN=svc-dashboard,OU=Service Accounts,..." /></label>
        <label>Bind password<input name="bind_password" type="password" autoComplete="new-password" placeholder={ldap.password_configured ? "Đã lưu · để trống nếu giữ nguyên" : "Mật khẩu service account"} /></label>
        <label>CA certificate cho LDAPS<textarea name="ca_certificate" rows={4} defaultValue={String(ldap.ca_certificate ?? "")} placeholder="-----BEGIN CERTIFICATE-----" /></label>
        <div className="form-grid"><label>Thuộc tính user<input name="user_attribute" defaultValue={String(ldap.user_attribute ?? "sAMAccountName")} /></label><label>Thuộc tính tên<input name="display_attribute" defaultValue={String(ldap.display_attribute ?? "displayName")} /></label></div>
        <div className="form-grid"><label>Nhãn domain<input name="domain_label" defaultValue={String(ldap.domain_label ?? "DOMAIN")} /></label><label>Role mặc định<select name="default_role" defaultValue={String(ldap.default_role ?? "viewer")}>{roles.filter((role) => role.name !== "admin").map((role) => <option key={role.name} value={role.name}>{role.displayName}</option>)}</select></label></div>
        <fieldset><legend>Group LDAP được phép đăng nhập</legend><div className="ldap-group-toolbar"><span>{ldapAllowedGroupDns.length ? `${ldapAllowedGroupDns.length} group đã chọn` : "Chưa giới hạn group"}</span><button type="button" className="button ghost compact" disabled={busy} onClick={() => void scanLdapDirectoryGroups()}>Quét groups</button></div><div className="choice-grid ldap-group-list">{ldapGroupOptions.map((group) => <label key={group.dn} title={group.dn}><input type="checkbox" name="allowed_group_dns" value={group.dn} defaultChecked={ldapAllowedGroupDns.includes(group.dn)} />{group.name}<small>{group.dn}</small></label>)}</div></fieldset>
        <div className={`resource-help${ldapAllowedGroupDns.length ? "" : " warning"}`}>{ldapAllowedGroupDns.length ? "Khi lưu, toàn bộ thành viên trực tiếp hoặc lồng nhau của các group đã chọn được đồng bộ vào danh sách với nhãn AD. " : "Chưa chọn group: LDAP vẫn cho phép user trong toàn Base DN đăng nhập nhưng không đồng bộ cả miền. Hãy quét và chọn ít nhất một group vận hành. "}Role mặc định chỉ áp dụng cho user AD mới; mọi role quản trị viên gán riêng vẫn được giữ ở lần đồng bộ sau.</div>
      </form>
    </ModalShell>}
    {showGroups && <ModalShell title="Groups của trạm vận hành" subtitle="Tạo group, chọn thành viên và dùng group để share máy chủ" close={() => setShowGroups(false)}><div className="role-manager"><aside><button type="button" className={groupEditor === "__new__" ? "active" : ""} onClick={() => setGroupEditor("__new__")}>＋ Tạo group mới</button>{groups.map((group) => <button type="button" key={group.id} className={groupEditor === group.id ? "active" : ""} onClick={() => setGroupEditor(group.id)}><b>{group.name}</b><small>{group.memberCount} thành viên</small></button>)}</aside><div className="role-editor">{groupEditor === null ? <div className="empty-state">Chọn group để sửa thành viên hoặc tạo group mới.</div> : <form key={groupEditor} className="resource-form" onSubmit={savePlatformGroup}><label>Tên group<input name="name" required minLength={2} maxLength={80} defaultValue={selectedGroup?.name ?? ""} /></label><label>Mô tả<textarea name="description" rows={2} defaultValue={selectedGroup?.description ?? ""} /></label><fieldset><legend>Thành viên Local và LDAP</legend><div className="choice-grid">{users.map((user) => <label key={user.id}><input type="checkbox" name="members" value={user.id} defaultChecked={selectedGroup?.memberIds.includes(user.id) ?? false} /><span>{user.displayName || user.username}<small>{user.username} · {user.source.toUpperCase()}</small></span></label>)}</div></fieldset><div className="modal-actions">{selectedGroup && <button type="button" className="button danger" disabled={busy} onClick={() => void deletePlatformGroup(selectedGroup)}>Xóa group</button>}<button className="button primary" disabled={busy}>Lưu group</button></div></form>}</div></div></ModalShell>}
    {showRoles && <ModalShell title="Roles & quyền hạn" subtitle="Bốn role có sẵn giữ baseline cố định; tạo role riêng để chọn đúng chức năng được phép" close={() => setShowRoles(false)}><div className="role-manager"><aside><button type="button" className={roleEditor === "__new__" ? "active" : ""} onClick={() => setRoleEditor("__new__")}>＋ Tạo role mới</button>{roles.map((role) => <button type="button" key={role.name} className={roleEditor === role.name ? "active" : ""} onClick={() => setRoleEditor(role.name)}><b>{role.displayName}</b><small>{role.system ? "Có sẵn · khóa" : role.name}</small></button>)}</aside><div className="role-editor">{roleEditor === null ? <div className="empty-state">Chọn một role để xem quyền hoặc tạo role tùy chỉnh.</div> : selectedRole?.system ? <><div className="role-editor-head"><div><h3>{selectedRole.displayName}</h3><p>{selectedRole.description}</p></div><span>Role có sẵn</span></div><div className="permission-summary">{permissions.filter((permission) => selectedRole.permissions.includes(permission.id)).map((permission) => <span key={permission.id}>{permission.label}</span>)}</div></> : <form key={roleEditor} className="resource-form" onSubmit={saveRole}><div className="form-grid"><label>Mã role<input name="name" required minLength={2} pattern="[a-z][a-z0-9_-]*" defaultValue={selectedRole?.name ?? ""} disabled={Boolean(selectedRole)} /></label><label>Tên hiển thị<input name="display_name" required defaultValue={selectedRole?.displayName ?? ""} /></label></div><label>Mô tả<textarea name="description" rows={2} defaultValue={selectedRole?.description ?? ""} /></label><div className="permission-groups">{Object.entries(groupedPermissions).map(([group, items]) => <fieldset key={group}><legend>{group}</legend>{items.map((permission) => <label key={permission.id} aria-label={`Cho phép ${permission.label}`}><input type="checkbox" name="permissions" value={permission.id} defaultChecked={selectedRole?.permissions.includes(permission.id) ?? false} /><span><b>{permission.label}</b><small>{permission.description}</small></span></label>)}</fieldset>)}</div><div className="modal-actions">{selectedRole && <button type="button" className="button danger" disabled={busy} onClick={() => void deleteRole(selectedRole)}>Xóa role</button>}<button className="button primary" disabled={busy}>Lưu role</button></div></form>}</div></div></ModalShell>}
  </section>;
}

function SessionModal({
  close,
  notify,
  server,
  token,
  isAdmin,
  manageCredentials,
}: {
  close: () => void;
  notify: (message: string) => void;
  server: Server;
  token: string;
  isAdmin: boolean;
  manageCredentials: () => void;
}) {
  const protocol = server.osFamily === "windows" ? "rdp" : "ssh";
  const [busy, setBusy] = useState(false);
  const [loadingCredentials, setLoadingCredentials] = useState(true);
  const [credentialId, setCredentialId] = useState("");
  const [credentialChoices, setCredentialChoices] = useState<Array<{ id: string; label: string; protocol: "ssh" | "rdp" }>>([]);
  const [credentialError, setCredentialError] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/v1/servers/${server.id}/remote-credentials?protocol=${protocol}`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    })
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.detail ?? "Không thể đọc tài khoản Remote");
        return payload.items ?? [];
      })
      .then((items) => {
        if (cancelled) return;
        setCredentialChoices(items);
        setCredentialId(items[0]?.id ?? "");
        setCredentialError("");
      })
      .catch((reason) => {
        if (!cancelled) setCredentialError(reason instanceof Error ? reason.message : "Không thể đọc tài khoản Remote");
      })
      .finally(() => {
        if (!cancelled) setLoadingCredentials(false);
      });
    return () => { cancelled = true; };
  }, [protocol, server.id, token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!credentialId) return;
    setBusy(true);
    const sessionWindow = window.open("about:blank", "_blank");
    if (sessionWindow) sessionWindow.opener = null;
    const pixelRatio = window.devicePixelRatio || 1;
    const width = Math.min(7680, Math.max(800, Math.round(window.screen.width * pixelRatio)));
    const height = Math.min(4320, Math.max(600, Math.round(window.screen.height * pixelRatio)));
    try {
      const response = await fetch("/api/v1/sessions/launch", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ server_id: server.id, protocol, credential_id: credentialId, width, height }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không thể tạo phiên");
      close();
      window.localStorage.removeItem("GUAC_AUTH_TOKEN");
      if (sessionWindow) sessionWindow.location.href = data.url;
      else window.location.href = data.url;
      notify(`Đã tạo phiên ${protocol.toUpperCase()} có ghi lại. Cho phép paste vào phiên; chặn copy dữ liệu từ máy chủ ra ngoài.`);
    } catch (reason) {
      sessionWindow?.close();
      notify(reason instanceof Error ? reason.message : "Không thể tạo phiên");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại" onClick={close} />
      <form className="modal" onSubmit={submit}>
        <div className="modal-head"><div><span className="modal-icon">↗</span><div><h2>{server.osFamily === "windows" ? "Remote Desktop" : "Phiên SSH"}</h2><p>{server.name} · phiên được ghi lại</p></div></div><button type="button" onClick={close}>×</button></div>
        {credentialError && <div className="danger-panel">{credentialError}</div>}
        <label>Tài khoản truy cập<select required value={credentialId} disabled={loadingCredentials || !credentialChoices.length} onChange={(event) => setCredentialId(event.target.value)}><option value="">{loadingCredentials ? "Đang đọc tài khoản…" : "Chọn tài khoản…"}</option>{credentialChoices.map((credential) => <option key={credential.id} value={credential.id}>{credential.label}</option>)}</select></label>
        {!loadingCredentials && !credentialChoices.length && <div className="warning-box"><b>Chưa có tài khoản được phép sử dụng</b><p>{isAdmin ? "Hãy tạo tài khoản Remote cho máy chủ này." : "Administrator cần share một tài khoản Remote cho bạn."}</p>{isAdmin && <button type="button" className="button ghost compact" onClick={manageCredentials}>Quản lý tài khoản Remote</button>}</div>}
        <div className="resource-help"><b>Clipboard một chiều:</b> có thể paste văn bản từ máy của bạn vào phiên SSH/RDP. Copy từ máy chủ về trình duyệt và truyền file native vẫn bị khóa.</div>
        <div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button primary" disabled={busy || loadingCredentials || !credentialId}>{busy ? "Đang kiểm tra tunnel và dịch vụ local…" : "Mở phiên & bắt đầu ghi"}</button></div>
      </form>
    </div>
  );
}
function CommandPalette({
  close,
  servers,
  select,
}: {
  close: () => void;
  servers: Server[];
  select: (server: Server) => void;
}) {
  const [value, setValue] = useState("");
  const matches = servers
    .filter((s) =>
      `${s.name} ${s.address} ${s.os}`
        .toLowerCase()
        .includes(value.toLowerCase()),
    )
    .slice(0, 5);
  return (
    <div className="modal-backdrop command-backdrop">
      <button
        className="modal-dismiss"
        type="button"
        aria-label="Đóng bảng lệnh"
        onClick={close}
      />
      <div className="command-palette">
        <div className="command-input">
          <span>⌕</span>
          <input
            aria-label="Tìm máy chủ hoặc hành động"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Tìm máy chủ hoặc hành động…"
          />
          <kbd>ESC</kbd>
        </div>
        <p>MÁY CHỦ</p>
        {matches.map((server) => (
          <button key={server.id} onClick={() => select(server)}>
            <span className={`os-avatar ${server.osFamily}`}>
              {server.osFamily === "windows" ? "W" : ">_"}
            </span>
            <span>
              <b>{server.name}</b>
              <small>
                {server.address} · {server.os}
              </small>
            </span>
            <em>↵</em>
          </button>
        ))}
      </div>
    </div>
  );
}
