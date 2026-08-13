"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type OSFamily = "linux" | "windows";
type Health = "healthy" | "warning" | "critical" | "offline";

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
};

const demoServers: Server[] = [
  { id: "srv-001", name: "web-prod-01", osFamily: "linux", os: "Ubuntu Server", version: "24.04.3 LTS", address: "10.20.1.11", environment: "Production", health: "healthy", agentVersion: "0.1.0", lastSeen: "8 giây trước", cpu: 34, memory: 62, disk: 48, uptime: "42 ngày", updates: 6, alerts: 0, services: 18, owner: "Platform", tags: ["web", "nginx", "hcm"] },
  { id: "srv-002", name: "ora-db-01", osFamily: "linux", os: "Oracle Linux", version: "8.10", address: "10.20.2.21", environment: "Production", health: "warning", agentVersion: "0.1.0", lastSeen: "12 giây trước", cpu: 71, memory: 84, disk: 69, uptime: "187 ngày", updates: 18, alerts: 2, services: 26, owner: "Database", tags: ["oracle", "database", "hn"] },
  { id: "srv-003", name: "legacy-app-07", osFamily: "linux", os: "Oracle Linux", version: "7.9", address: "10.20.3.47", environment: "Production", health: "critical", agentVersion: "0.1.0", lastSeen: "31 giây trước", cpu: 92, memory: 89, disk: 91, uptime: "302 ngày", updates: 43, alerts: 4, services: 15, owner: "ERP", tags: ["legacy", "erp"] },
  { id: "srv-004", name: "dc-hcm-01", osFamily: "windows", os: "Windows Server", version: "2025 Datacenter", address: "10.30.1.10", environment: "Production", health: "healthy", agentVersion: "0.1.0", lastSeen: "6 giây trước", cpu: 18, memory: 47, disk: 38, uptime: "19 ngày", updates: 2, alerts: 0, services: 92, owner: "Identity", tags: ["ad-ds", "dns", "hcm"] },
  { id: "srv-005", name: "files-hn-02", osFamily: "windows", os: "Windows Server", version: "2025 Standard", address: "10.30.2.22", environment: "Production", health: "warning", agentVersion: "0.1.0", lastSeen: "18 giây trước", cpu: 42, memory: 76, disk: 86, uptime: "73 ngày", updates: 9, alerts: 1, services: 71, owner: "Workplace", tags: ["files", "smb", "hn"] },
  { id: "srv-006", name: "build-stg-01", osFamily: "windows", os: "Windows Server", version: "2025 Standard", address: "10.40.1.31", environment: "Staging", health: "offline", agentVersion: "0.1.0", lastSeen: "17 phút trước", cpu: 0, memory: 0, disk: 54, uptime: "—", updates: 12, alerts: 1, services: 0, owner: "Engineering", tags: ["build", "staging"] },
];

const navItems = [
  { id: "overview", icon: "⌂", label: "Tổng quan" },
  { id: "linux", icon: "L", label: "Máy chủ Linux", count: 3 },
  { id: "windows", icon: "W", label: "Máy chủ Windows", count: 3 },
  { id: "sessions", icon: "↗", label: "Phiên truy cập", count: 2 },
  { id: "jobs", icon: "▶", label: "Công việc", count: 5 },
  { id: "audit", icon: "≡", label: "Nhật ký kiểm toán" },
  { id: "access", icon: "◎", label: "Người dùng & vai trò" },
];

const healthLabel: Record<Health, string> = { healthy: "Ổn định", warning: "Cảnh báo", critical: "Nguy cấp", offline: "Mất kết nối" };

function MiniBar({ value, dangerAt = 85 }: { value: number; dangerAt?: number }) {
  const tone = value >= dangerAt ? "danger" : value >= 70 ? "warn" : "good";
  return <span className="mini-bar" aria-label={`${value}%`}><i className={tone} style={{ width: `${value}%` }} /></span>;
}

function ServerTable({ servers, onSelect }: { servers: Server[]; onSelect: (server: Server) => void }) {
  return (
    <div className="table-scroll">
      <table className="server-table">
        <thead><tr><th>Máy chủ</th><th>Hệ điều hành</th><th>Trạng thái</th><th>CPU</th><th>Bộ nhớ</th><th>Ổ đĩa</th><th>Cập nhật</th><th /></tr></thead>
        <tbody>
          {servers.map((server) => (
            <tr key={server.id} role="button" onClick={() => onSelect(server)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onSelect(server)}>
              <td><div className="server-name"><span className={`os-avatar ${server.osFamily}`}>{server.osFamily === "windows" ? "W" : ">_"}</span><span><strong>{server.name}</strong><small>{server.address} · {server.environment}</small></span></div></td>
              <td><strong className="cell-main">{server.os}</strong><small>{server.version}</small></td>
              <td><span className={`status ${server.health}`}><i />{healthLabel[server.health]}</span><small>{server.lastSeen}</small></td>
              <td><span className="metric-value">{server.cpu}%</span><MiniBar value={server.cpu} /></td>
              <td><span className="metric-value">{server.memory}%</span><MiniBar value={server.memory} /></td>
              <td><span className="metric-value">{server.disk}%</span><MiniBar value={server.disk} dangerAt={90} /></td>
              <td><span className={server.updates > 15 ? "update-count hot" : "update-count"}>{server.updates}</span></td>
              <td><button className="row-more" aria-label={`Mở ${server.name}`} onClick={(e) => { e.stopPropagation(); onSelect(server); }}>•••</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function OpsConsole() {
  const [servers, setServers] = useState(demoServers);
  const [token, setToken] = useState("");
  const [authReady, setAuthReady] = useState(false);
  const [active, setActive] = useState("overview");
  const [selected, setSelected] = useState<Server | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | Health>("all");
  const [modal, setModal] = useState<"user" | "job" | "command" | "session" | null>(null);
  const [toast, setToast] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setToken(window.sessionStorage.getItem("tram_ops_token") ?? "");
      setAuthReady(true);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!token) return;
    let mounted = true;
    fetch("/api/v1/servers", { headers: { Accept: "application/json", Authorization: `Bearer ${token}` } })
      .then((response) => {
        if (response.status === 401) {
          window.sessionStorage.removeItem("tram_ops_token");
          setToken("");
          return Promise.reject();
        }
        return response.ok ? response.json() : Promise.reject();
      })
      .then((data) => { if (mounted && Array.isArray(data.items)) setServers(data.items); })
      .catch(() => undefined)
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [token]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setModal("command"); }
      if (event.key === "Escape") { setModal(null); setSelected(null); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const scope = active === "linux" || active === "windows" ? active : null;
  const visibleServers = useMemo(() => servers.filter((server) => {
    const matchesOS = !scope || server.osFamily === scope;
    const matchesHealth = filter === "all" || server.health === filter;
    const haystack = `${server.name} ${server.address} ${server.os} ${server.version} ${server.tags.join(" ")}`.toLowerCase();
    return matchesOS && matchesHealth && haystack.includes(query.toLowerCase());
  }), [servers, scope, filter, query]);

  const online = servers.filter((s) => s.health !== "offline").length;
  const warnings = servers.reduce((sum, s) => sum + s.alerts, 0);
  const updates = servers.reduce((sum, s) => sum + s.updates, 0);
  const navCount = (id: string, fallback?: number) => id === "linux" ? servers.filter((server) => server.osFamily === "linux").length : id === "windows" ? servers.filter((server) => server.osFamily === "windows").length : fallback;

  function notify(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(""), 3200);
  }

  async function submitUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const form = new FormData(event.currentTarget);
    const parameters: Record<string, unknown> = { username: form.get("username"), groups: [form.get("group")] };
    if (form.get("password")) parameters.password = form.get("password");
    try {
      const response = await fetch("/api/v1/jobs", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ server_id: selected.id, action: "user.create", parameters, reason: form.get("reason"), require_approval: true }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không thể tạo công việc");
      setModal(null);
      notify(`Đã gửi yêu cầu ${data.id.slice(0, 8)} tạo tài khoản tới ${selected.name}.`);
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể tạo công việc");
    }
  }

  const title = active === "linux" ? "Máy chủ Linux" : active === "windows" ? "Máy chủ Windows" : active === "sessions" ? "Phiên truy cập" : active === "jobs" ? "Công việc vận hành" : active === "audit" ? "Nhật ký kiểm toán" : active === "access" ? "Người dùng & vai trò" : "Trung tâm vận hành";

  if (!authReady) return <div className="auth-loading">Đang khởi tạo phiên bảo mật…</div>;
  if (!token) return <LoginScreen onLogin={(nextToken) => { window.sessionStorage.setItem("tram_ops_token", nextToken); setToken(nextToken); }} />;

  return (
    <main className="shell">
      <aside className="sidebar">
        <button className="brand" onClick={() => setActive("overview")} aria-label="Về tổng quan"><span className="brand-mark">V</span><span><b>TRẠM</b><small>VẬN HÀNH</small></span></button>
        <nav aria-label="Điều hướng chính">
          <p className="nav-heading">HẠ TẦNG</p>
          {navItems.slice(0, 3).map((item) => { const count = navCount(item.id, item.count); return <button key={item.id} className={active === item.id ? "active" : ""} onClick={() => { setActive(item.id); setSelected(null); }}><span className="nav-icon">{item.icon}</span>{item.label}{count !== undefined && <em>{count}</em>}</button>; })}
          <p className="nav-heading spaced">VẬN HÀNH</p>
          {navItems.slice(3, 6).map((item) => { const count = navCount(item.id, item.count); return <button key={item.id} className={active === item.id ? "active" : ""} onClick={() => { setActive(item.id); setSelected(null); }}><span className="nav-icon">{item.icon}</span>{item.label}{count !== undefined && <em>{count}</em>}</button>; })}
          <p className="nav-heading spaced">QUẢN TRỊ</p>
          {navItems.slice(6).map((item) => <button key={item.id} className={active === item.id ? "active" : ""} onClick={() => { setActive(item.id); setSelected(null); }}><span className="nav-icon">{item.icon}</span>{item.label}</button>)}
        </nav>
        <div className="security-card"><div className="security-title"><span>◆</span><b>Kết nối được bảo vệ</b></div><p>Agent mTLS · TLS 1.3</p><div><i />CA nội bộ hoạt động</div></div>
        <button className="profile" onClick={() => { window.sessionStorage.removeItem("tram_ops_token"); setToken(""); }} title="Đăng xuất"><span className="profile-avatar">AD</span><span><b>Administrator</b><small>Nhấn để đăng xuất</small></span><strong>⌄</strong></button>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="search"><span>⌕</span><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Tìm máy chủ, IP hoặc nhãn..." aria-label="Tìm kiếm" /><kbd>Ctrl K</kbd></div>
          <div className="top-actions"><button className="icon-button" aria-label="Thông báo">♢<span className="notification-dot" /></button><button className="help">?</button><span className="now"><i />Hệ thống ổn định</span></div>
        </header>

        <div className="content">
          <div className="page-head"><div><p className="eyebrow">CONTROL PLANE · AP-SOUTHEAST</p><h1>{title}</h1><p>Giám sát, truy cập và thực thi tác vụ an toàn trên toàn bộ máy chủ.</p></div><div className="head-actions"><button className="button ghost" onClick={() => notify("Đang làm mới dữ liệu từ các agent…")}>↻ Làm mới</button><button className="button primary" onClick={() => setModal("job")}>＋ Tạo công việc</button></div></div>

          {active === "overview" && <>
            <section className="stat-grid" aria-label="Tóm tắt hạ tầng">
              <article className="stat-card"><div className="stat-top"><span className="stat-icon blue">▦</span><span className="delta good">+2 tháng này</span></div><strong>{servers.length}</strong><h3>Tổng máy chủ</h3><p><i className="online-dot" /> {online} đang kết nối</p></article>
              <article className="stat-card"><div className="stat-top"><span className="stat-icon green">✓</span><span className="delta good">{Math.round(online / servers.length * 100)}%</span></div><strong>{online}</strong><h3>Agent trực tuyến</h3><p><i className="muted-dot" /> {servers.length - online} mất kết nối</p></article>
              <article className="stat-card"><div className="stat-top"><span className="stat-icon amber">!</span><span className="delta warn">Cần xử lý</span></div><strong>{warnings}</strong><h3>Cảnh báo đang mở</h3><p>{servers.filter(s => s.health === "critical").length} nguy cấp · {servers.filter(s => s.health === "warning").length} cảnh báo</p></article>
              <article className="stat-card"><div className="stat-top"><span className="stat-icon violet">↥</span><span className="delta">7 ngày</span></div><strong>{updates}</strong><h3>Bản vá chờ cài</h3><p>{servers.filter(s => s.updates > 0).length} máy chủ bị ảnh hưởng</p></article>
            </section>

            <section className="overview-grid">
              <article className="panel health-panel"><div className="panel-head"><div><h2>Sức khỏe hạ tầng</h2><p>Trạng thái 24 giờ gần nhất</p></div><button>24 giờ⌄</button></div><div className="health-chart"><div className="donut" style={{ "--healthy": `${Math.round(online / servers.length * 100) * 3.6}deg` } as React.CSSProperties}><span><b>{Math.round(online / servers.length * 100)}%</b><small>khả dụng</small></span></div><div className="health-legend"><div><i className="green-bg" /><span>Ổn định<small>{servers.filter(s => s.health === "healthy").length} máy chủ</small></span><b>{servers.filter(s => s.health === "healthy").length}</b></div><div><i className="amber-bg" /><span>Cảnh báo<small>Cần theo dõi</small></span><b>{servers.filter(s => s.health === "warning").length}</b></div><div><i className="red-bg" /><span>Nguy cấp / Offline<small>Cần xử lý ngay</small></span><b>{servers.filter(s => ["critical", "offline"].includes(s.health)).length}</b></div></div></div></article>
              <article className="panel activity-panel"><div className="panel-head"><div><h2>Hoạt động gần đây</h2><p>Audit log trực tiếp</p></div><button onClick={() => setActive("audit")}>Xem tất cả →</button></div><div className="activity-list">
                <div><span className="activity-icon green">✓</span><p><b>Cập nhật gói thành công</b><small>web-prod-01 · bởi Minh Trần</small></p><time>2 phút</time></div>
                <div><span className="activity-icon blue">↗</span><p><b>Mở phiên SSH</b><small>ora-db-01 · bởi Anh Nguyễn</small></p><time>8 phút</time></div>
                <div><span className="activity-icon violet">＋</span><p><b>Đã tạo local user</b><small>dc-hcm-01 · svc_backup</small></p><time>23 phút</time></div>
                <div><span className="activity-icon amber">!</span><p><b>Dung lượng ổ đĩa vượt ngưỡng</b><small>legacy-app-07 · /var</small></p><time>41 phút</time></div>
              </div></article>
            </section>
          </>}

          {active === "sessions" ? <SessionsView notify={notify} /> : active === "jobs" ? <JobsView /> : active === "audit" ? <AuditView /> : active === "access" ? <AccessView notify={notify} /> : <section className="panel fleet-panel"><div className="panel-head fleet-head"><div><h2>{scope ? `Danh sách ${scope === "linux" ? "Linux" : "Windows"}` : "Toàn bộ máy chủ"}</h2><p>{visibleServers.length} máy chủ · dữ liệu agent theo thời gian thực</p></div><div className="filters"><button className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>Tất cả</button><button className={filter === "healthy" ? "active" : ""} onClick={() => setFilter("healthy")}>Ổn định</button><button className={filter === "warning" ? "active" : ""} onClick={() => setFilter("warning")}>Cảnh báo</button><button className={filter === "critical" ? "active" : ""} onClick={() => setFilter("critical")}>Nguy cấp</button></div></div>{loading ? <div className="loading-line" /> : null}<ServerTable servers={visibleServers} onSelect={setSelected} /></section>}
        </div>
      </section>

      {selected && <ServerDrawer server={selected} close={() => setSelected(null)} openUser={() => setModal("user")} openSession={() => setModal("session")} notify={notify} />}
      {modal === "user" && <div className="modal-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại" onClick={() => setModal(null)} /><form className="modal" onSubmit={submitUser}><div className="modal-head"><div><span className="modal-icon">＋</span><div><h2>Tạo tài khoản cục bộ</h2><p>{selected?.name ?? "Chọn máy chủ đích"}</p></div></div><button type="button" onClick={() => setModal(null)}>×</button></div><label>Tên đăng nhập<input required name="username" placeholder="vd. ops.anh" pattern="[a-zA-Z0-9._-]+" /></label>{selected?.osFamily === "windows" && <label>Mật khẩu tạm thời<input required type="password" name="password" minLength={12} autoComplete="new-password" placeholder="Tối thiểu 12 ký tự" /></label>}<div className="form-grid"><label>Nhóm quyền<select name="group" defaultValue={selected?.osFamily === "windows" ? "Remote Desktop Users" : selected?.os.includes("Ubuntu") ? "sudo" : "wheel"}><option>sudo</option><option>wheel</option><option>sshlogin</option><option>Remote Desktop Users</option><option>OpenSSH Users</option><option>Administrators</option></select></label><label>Hết hạn<input type="date" name="expires" /></label></div><label>Lý do / mã ticket<textarea required name="reason" rows={2} placeholder="CHG-1234 · Cấp quyền vận hành…" /></label><div className="warning-box"><b>Chính sách đặc quyền</b><p>Tài khoản có quyền sudo/Administrators cần một người khác phê duyệt trước khi agent thực thi.</p></div><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary">Gửi yêu cầu</button></div></form></div>}
      {modal === "job" && <JobModal close={() => setModal(null)} notify={notify} servers={servers} token={token} />}
      {modal === "session" && selected && <SessionModal close={() => setModal(null)} notify={notify} server={selected} token={token} />}
      {modal === "command" && <CommandPalette close={() => setModal(null)} servers={servers} select={(server) => { setSelected(server); setModal(null); }} />}
      {toast && <div className="toast"><span>✓</span>{toast}</div>}
    </main>
  );
}

function LoginScreen({ onLogin }: { onLogin: (token: string) => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: form.get("username"), password: form.get("password") }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không thể đăng nhập");
      onLogin(data.access_token);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể đăng nhập");
    } finally {
      setBusy(false);
    }
  }
  return <div className="login-page"><div className="login-glow" /><form className="login-card" onSubmit={submit}><div className="login-brand"><span className="brand-mark">V</span><div><b>TRẠM</b><small>VẬN HÀNH</small></div></div><p className="login-eyebrow">SECURE CONTROL PLANE</p><h1>Đăng nhập hệ thống</h1><p className="login-copy">Quản trị tập trung Windows Server và Linux qua kết nối được mã hóa.</p><label>Tên đăng nhập<input name="username" autoComplete="username" required placeholder="admin" /></label><label>Mật khẩu<input type="password" name="password" autoComplete="current-password" required placeholder="••••••••••••••" /></label>{error && <div className="login-error">{error}</div>}<button className="button primary" disabled={busy}>{busy ? "Đang xác thực…" : "Đăng nhập an toàn"}</button><div className="login-security"><span>◆</span><p><b>TLS 1.3 · RBAC · Audit bất biến</b><small>Không chia sẻ thông tin đăng nhập với bất kỳ ai.</small></p></div></form></div>;
}

function ServerDrawer({ server, close, openUser, openSession, notify }: { server: Server; close: () => void; openUser: () => void; openSession: () => void; notify: (message: string) => void }) {
  return <><button className="drawer-scrim" onClick={close} aria-label="Đóng chi tiết" /><aside className="drawer"><div className="drawer-top"><button onClick={close}>×</button><span className={`os-avatar large ${server.osFamily}`}>{server.osFamily === "windows" ? "W" : ">_"}</span><div><span className={`status ${server.health}`}><i />{healthLabel[server.health]}</span><h2>{server.name}</h2><p>{server.os} {server.version}</p></div><button className="row-more">•••</button></div><div className="drawer-actions"><button className="connect" onClick={openSession}><span>↗</span><b>{server.osFamily === "windows" ? "Remote Desktop" : "Mở SSH"}</b><small>Qua gateway bảo mật</small></button><button onClick={() => notify("Đã gửi yêu cầu thu thập thông tin mới.")}><span>↻</span><b>Làm mới</b><small>Đồng bộ agent</small></button></div><div className="drawer-tabs"><button className="active">Tổng quan</button><button>Dịch vụ</button><button>Tài khoản</button><button>Nhật ký</button></div><div className="drawer-body"><h3>Tài nguyên</h3><div className="resource-grid"><div><span><b>CPU</b><strong>{server.cpu}%</strong></span><MiniBar value={server.cpu} /></div><div><span><b>Bộ nhớ</b><strong>{server.memory}%</strong></span><MiniBar value={server.memory} /></div><div><span><b>Ổ đĩa</b><strong>{server.disk}%</strong></span><MiniBar value={server.disk} dangerAt={90} /></div></div><h3>Thông tin hệ thống</h3><dl className="detail-list"><div><dt>Địa chỉ quản trị</dt><dd>{server.address}</dd></div><div><dt>Môi trường</dt><dd><span className="tag">{server.environment}</span></dd></div><div><dt>Thời gian hoạt động</dt><dd>{server.uptime}</dd></div><div><dt>Dịch vụ</dt><dd>{server.services} đang chạy</dd></div><div><dt>Agent</dt><dd>v{server.agentVersion} · mTLS</dd></div><div><dt>Đơn vị phụ trách</dt><dd>{server.owner}</dd></div></dl><h3>Tác vụ nhanh</h3><div className="quick-actions"><button onClick={openUser}><span>＋</span>Tạo tài khoản</button><button onClick={() => notify(`Đã xếp lịch cài ${server.updates} bản vá.`)}><span>↥</span>Cài bản vá <em>{server.updates}</em></button><button onClick={() => notify("Đang tải danh sách dịch vụ…")}><span>⚙</span>Quản lý dịch vụ</button><button onClick={() => notify("Đã mở trình xem event/journal.")}><span>≡</span>Xem nhật ký</button></div></div></aside></>;
}

function SessionsView({ notify }: { notify: (message: string) => void }) {
  return <section className="panel view-panel"><div className="panel-head"><div><h2>Phiên đang hoạt động</h2><p>Mọi phiên đều được ghi lại và gắn với danh tính người vận hành.</p></div><span className="live-pill"><i />2 đang trực tiếp</span></div><div className="session-list"><article><span className="session-protocol ssh">SSH</span><div><b>ora-db-01</b><small>10.20.2.21 · Anh Nguyễn</small></div><time>00:18:42</time><span className="recording">● ĐANG GHI</span><button onClick={() => notify("Mở lại phiên SSH đang hoạt động…")}>Mở phiên →</button></article><article><span className="session-protocol rdp">RDP</span><div><b>files-hn-02</b><small>10.30.2.22 · Minh Trần</small></div><time>00:07:16</time><span className="recording">● ĐANG GHI</span><button onClick={() => notify("Mở lại phiên RDP đang hoạt động…")}>Mở phiên →</button></article></div><div className="subhead"><div><h3>Bản ghi gần đây</h3><p>Lưu giữ 180 ngày · mã hóa AES-256 phía lưu trữ</p></div><button className="button ghost">Xuất báo cáo</button></div><div className="recording-list"><div><span className="play">▶</span><p><b>web-prod-01 · SSH</b><small>12/08/2026, 16:42 · 24 phút · Hoàng Lê</small></p><span className="verified">✓ Đã xác minh</span><button>Phát lại</button></div><div><span className="play">▶</span><p><b>dc-hcm-01 · RDP</b><small>12/08/2026, 14:08 · 51 phút · Anh Nguyễn</small></p><span className="verified">✓ Đã xác minh</span><button>Phát lại</button></div><div><span className="play">▶</span><p><b>legacy-app-07 · SSH</b><small>11/08/2026, 21:13 · 13 phút · Minh Trần</small></p><span className="verified">✓ Đã xác minh</span><button>Phát lại</button></div></div></section>;
}

function JobsView() {
  const jobs = [{ name: "Cài bản vá bảo mật tháng 08", target: "4 máy chủ", owner: "Anh Nguyễn", status: "Đang chạy", progress: 68 }, { name: "Tạo tài khoản svc_backup", target: "dc-hcm-01", owner: "Minh Trần", status: "Chờ phê duyệt", progress: 0 }, { name: "Khởi động lại nginx", target: "web-prod-01", owner: "Hoàng Lê", status: "Hoàn tất", progress: 100 }, { name: "Kiểm tra dung lượng /var", target: "3 máy chủ Linux", owner: "Hệ thống", status: "Hoàn tất", progress: 100 }];
  return <section className="panel view-panel"><div className="panel-head"><div><h2>Luồng công việc</h2><p>Tác vụ có cấu trúc, kiểm soát phê duyệt và có thể truy vết.</p></div><button className="button ghost">Bộ lọc⌄</button></div><div className="jobs-table"><div className="jobs-row head"><span>Công việc</span><span>Đích</span><span>Người tạo</span><span>Tiến độ</span><span>Trạng thái</span></div>{jobs.map((job) => <div className="jobs-row" key={job.name}><p><b>{job.name}</b><small>JOB-{Math.floor(2100 + job.progress)}</small></p><span>{job.target}</span><span>{job.owner}</span><div className="job-progress"><MiniBar value={job.progress} /><small>{job.progress}%</small></div><span className={`job-state ${job.status === "Hoàn tất" ? "done" : job.status === "Đang chạy" ? "running" : "pending"}`}>{job.status}</span></div>)}</div></section>;
}

function AuditView() {
  const rows = [{ time: "11:08:42", actor: "anh.nguyen", action: "session.ssh.open", target: "ora-db-01", result: "Thành công", ip: "172.18.4.21" }, { time: "10:56:17", actor: "minh.tran", action: "user.create.request", target: "dc-hcm-01", result: "Chờ duyệt", ip: "172.18.4.18" }, { time: "10:41:03", actor: "system", action: "agent.checkin.missed", target: "build-stg-01", result: "Cảnh báo", ip: "—" }, { time: "10:22:51", actor: "hoang.le", action: "service.restart", target: "web-prod-01/nginx", result: "Thành công", ip: "172.18.4.32" }, { time: "09:58:04", actor: "anh.nguyen", action: "patch.schedule", target: "linux:production", result: "Thành công", ip: "172.18.4.21" }];
  return <section className="panel view-panel"><div className="panel-head"><div><h2>Nhật ký bất biến</h2><p>Chuỗi sự kiện có hash liên kết, hỗ trợ điều tra và tuân thủ.</p></div><div className="audit-integrity">◆ Chuỗi hash hợp lệ</div></div><div className="audit-table"><div className="audit-row head"><span>Thời gian</span><span>Chủ thể</span><span>Hành động</span><span>Đối tượng</span><span>Kết quả</span><span>IP nguồn</span></div>{rows.map((row) => <div className="audit-row" key={row.time + row.action}><time>{row.time}</time><b>{row.actor}</b><code>{row.action}</code><span>{row.target}</span><span className={row.result === "Thành công" ? "result-good" : "result-warn"}>{row.result}</span><span>{row.ip}</span></div>)}</div></section>;
}

function AccessView({ notify }: { notify: (message: string) => void }) {
  return <div className="access-grid"><section className="panel view-panel"><div className="panel-head"><div><h2>Vai trò truy cập</h2><p>Quyền tối thiểu theo chức năng.</p></div><button className="button primary" onClick={() => notify("Mở trình tạo vai trò mới…")}>＋ Vai trò</button></div><div className="role-list"><article><span>AD</span><p><b>Platform Admin</b><small>Toàn quyền · cần MFA · 3 thành viên</small></p><em>28 quyền</em></article><article><span>OP</span><p><b>Server Operator</b><small>Vận hành không quản lý RBAC · 8 thành viên</small></p><em>17 quyền</em></article><article><span>DB</span><p><b>Database Team</b><small>Chỉ máy chủ nhãn database · 4 thành viên</small></p><em>9 quyền</em></article><article><span>AU</span><p><b>Auditor</b><small>Chỉ đọc log và bản ghi · 2 thành viên</small></p><em>5 quyền</em></article></div></section><aside className="panel policy-panel"><h2>Kiểm soát phiên</h2><div className="policy-toggle"><span><b>Bắt buộc MFA</b><small>Mọi tài khoản đặc quyền</small></span><input aria-label="Bắt buộc MFA" type="checkbox" defaultChecked /></div><div className="policy-toggle"><span><b>Ghi lại phiên</b><small>Không cho người dùng tắt</small></span><input aria-label="Ghi lại phiên" type="checkbox" defaultChecked /></div><div className="policy-toggle"><span><b>Phê duyệt 4 mắt</b><small>Cho tác vụ nguy hiểm</small></span><input aria-label="Phê duyệt 4 mắt" type="checkbox" defaultChecked /></div><div className="policy-toggle"><span><b>Che dữ liệu nhạy cảm</b><small>Trong typescript SSH</small></span><input aria-label="Che dữ liệu nhạy cảm" type="checkbox" defaultChecked /></div></aside></div>;
}

function JobModal({ close, notify, servers, token }: { close: () => void; notify: (message: string) => void; servers: Server[]; token: string }) {
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const form = new FormData(event.currentTarget); try { const response = await fetch("/api/v1/jobs", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ server_id: form.get("server_id"), action: form.get("action"), parameters: {}, reason: form.get("reason"), require_approval: true }) }); const data = await response.json(); if (!response.ok) throw new Error(data.detail ?? "Không thể tạo công việc"); close(); notify(`Đã tạo công việc ${data.id.slice(0, 8)} · ${data.status}.`); } catch (reason) { notify(reason instanceof Error ? reason.message : "Không thể tạo công việc"); } }
  return <div className="modal-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại" onClick={close} /><form className="modal" onSubmit={submit}><div className="modal-head"><div><span className="modal-icon">▶</span><div><h2>Tạo công việc</h2><p>Thực thi qua agent với audit đầy đủ</p></div></div><button type="button" onClick={close}>×</button></div><label>Máy chủ<select name="server_id" required defaultValue=""><option value="" disabled>Chọn máy chủ…</option>{servers.map((server) => <option key={server.id} value={server.id}>{server.name} · {server.os}</option>)}</select></label><label>Hành động<select name="action"><option value="inventory.collect">Thu thập inventory</option><option value="patch.scan">Liệt kê bản vá</option><option value="patch.install_security">Cài bản vá bảo mật</option><option value="service.list">Liệt kê dịch vụ</option><option value="process.list">Liệt kê tiến trình</option><option value="firewall.list">Xem firewall</option><option value="system.reboot">Khởi động lại máy chủ</option></select></label><label>Lý do thay đổi<textarea name="reason" required placeholder="Mã ticket, mục đích và ảnh hưởng dự kiến…" rows={3} /></label><label className="check"><input type="checkbox" defaultChecked /> Yêu cầu phê duyệt trước khi chạy</label><div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button primary">Tạo công việc</button></div></form></div>;
}

function SessionModal({ close, notify, server, token }: { close: () => void; notify: (message: string) => void; server: Server; token: string }) {
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const form = new FormData(event.currentTarget); const protocol = server.osFamily === "windows" ? "rdp" : "ssh"; const sessionWindow = window.open("about:blank", "_blank"); if (sessionWindow) sessionWindow.opener = null; try { const response = await fetch("/api/v1/sessions/launch", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ server_id: server.id, protocol, username: form.get("username"), password: form.get("password") }) }); const data = await response.json(); if (!response.ok) throw new Error(data.detail ?? "Không thể tạo phiên"); close(); if (sessionWindow) sessionWindow.location.href = data.url; else window.location.href = data.url; notify(`Đã tạo phiên ${protocol.toUpperCase()} có ghi lại.`); } catch (reason) { sessionWindow?.close(); notify(reason instanceof Error ? reason.message : "Không thể tạo phiên"); } }
  return <div className="modal-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại" onClick={close} /><form className="modal" onSubmit={submit}><div className="modal-head"><div><span className="modal-icon">↗</span><div><h2>{server.osFamily === "windows" ? "Remote Desktop" : "Phiên SSH"}</h2><p>{server.name} · phiên được ghi lại</p></div></div><button type="button" onClick={close}>×</button></div><label>Tên đăng nhập<input name="username" required autoComplete="username" /></label><label>Mật khẩu phiên<input type="password" name="password" required autoComplete="current-password" /></label><div className="warning-box"><b>Thông tin xác thực dùng một lần</b><p>Mật khẩu chỉ được đưa vào token Guacamole mã hóa, không được lưu trong database hoặc audit log.</p></div><div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button primary">Mở phiên & bắt đầu ghi</button></div></form></div>;
}

function CommandPalette({ close, servers, select }: { close: () => void; servers: Server[]; select: (server: Server) => void }) {
  const [value, setValue] = useState("");
  const matches = servers.filter((s) => `${s.name} ${s.address}`.includes(value.toLowerCase())).slice(0, 5);
  return <div className="modal-backdrop command-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng bảng lệnh" onClick={close} /><div className="command-palette"><div className="command-input"><span>⌕</span><input aria-label="Tìm máy chủ hoặc hành động" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Tìm máy chủ hoặc hành động…" /><kbd>ESC</kbd></div><p>MÁY CHỦ</p>{matches.map((server) => <button key={server.id} onClick={() => select(server)}><span className={`os-avatar ${server.osFamily}`}>{server.osFamily === "windows" ? "W" : ">_"}</span><span><b>{server.name}</b><small>{server.address} · {server.os}</small></span><em>↵</em></button>)}</div></div>;
}
