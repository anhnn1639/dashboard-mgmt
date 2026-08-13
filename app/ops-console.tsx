"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type OSFamily = "linux" | "windows";
type Health = "healthy" | "warning" | "critical" | "offline";

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

const navItems = [
  { id: "overview", icon: "⌂", label: "Tổng quan" },
  { id: "linux", icon: "L", label: "Máy chủ Linux", count: 3 },
  { id: "windows", icon: "W", label: "Máy chủ Windows", count: 3 },
  { id: "sessions", icon: "↗", label: "Phiên truy cập" },
  { id: "jobs", icon: "▶", label: "Công việc" },
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
  const [servers, setServers] = useState<Server[]>([]);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [setupStatusError, setSetupStatusError] = useState("");
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
    let mounted = true;
    fetch("/api/v1/setup/status", { headers: { Accept: "application/json" } })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Control plane chưa sẵn sàng")))
      .then((data: SetupStatus) => { if (mounted) setSetupStatus(data); })
      .catch((reason) => { if (mounted) setSetupStatusError(reason instanceof Error ? reason.message : "Không thể kiểm tra trạng thái hệ thống"); });
    return () => { mounted = false; };
  }, []);

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
    const loadServers = () => fetch("/api/v1/servers", { headers: { Accept: "application/json", Authorization: `Bearer ${token}` } })
      .then((response) => {
        if (response.status === 401) {
          window.sessionStorage.removeItem("tram_ops_token");
          setToken("");
          throw new Error("Unauthorized");
        }
        return response.ok ? response.json() : Promise.reject(new Error("Unable to load servers"));
      })
      .then((data) => { if (mounted && Array.isArray(data.items)) setServers(data.items); })
      .catch(() => undefined)
      .finally(() => { if (mounted) setLoading(false); });
    void loadServers();
    const timer = window.setInterval(() => { void loadServers(); }, 15_000);
    return () => { mounted = false; window.clearInterval(timer); };
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
  const availability = servers.length ? Math.round(online / servers.length * 100) : 0;
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

  if (setupStatusError) return <SystemUnavailable message={setupStatusError} />;
  if (!setupStatus || !authReady) return <div className="auth-loading">Đang kiểm tra cấu hình hệ thống…</div>;
  if (setupStatus.setupRequired) return <SetupScreen status={setupStatus} onComplete={(dashboardUrl) => { window.sessionStorage.removeItem("tram_ops_token"); setToken(""); setSetupStatus({ ...setupStatus, setupRequired: false, databaseConfigured: true, databaseConnected: true, schemaReady: true, adminExists: true, secretsReady: true, dashboardUrl, status: "ready" }); }} />;
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
              <article className="stat-card"><div className="stat-top"><span className="stat-icon blue">▦</span><span className="delta good">PostgreSQL</span></div><strong>{servers.length}</strong><h3>Tổng máy chủ</h3><p><i className="online-dot" /> {online} đang kết nối</p></article>
              <article className="stat-card"><div className="stat-top"><span className="stat-icon green">✓</span><span className="delta good">{availability}%</span></div><strong>{online}</strong><h3>Agent trực tuyến</h3><p><i className="muted-dot" /> {servers.length - online} mất kết nối</p></article>
              <article className="stat-card"><div className="stat-top"><span className="stat-icon amber">!</span><span className="delta warn">Cần xử lý</span></div><strong>{warnings}</strong><h3>Cảnh báo đang mở</h3><p>{servers.filter(s => s.health === "critical").length} nguy cấp · {servers.filter(s => s.health === "warning").length} cảnh báo</p></article>
              <article className="stat-card"><div className="stat-top"><span className="stat-icon violet">↥</span><span className="delta">7 ngày</span></div><strong>{updates}</strong><h3>Bản vá chờ cài</h3><p>{servers.filter(s => s.updates > 0).length} máy chủ bị ảnh hưởng</p></article>
            </section>

            <section className="overview-grid">
              <article className="panel health-panel"><div className="panel-head"><div><h2>Sức khỏe hạ tầng</h2><p>Trạng thái 24 giờ gần nhất</p></div><button>24 giờ⌄</button></div><div className="health-chart"><div className="donut" style={{ "--healthy": `${availability * 3.6}deg` } as React.CSSProperties}><span><b>{availability}%</b><small>khả dụng</small></span></div><div className="health-legend"><div><i className="green-bg" /><span>Ổn định<small>{servers.filter(s => s.health === "healthy").length} máy chủ</small></span><b>{servers.filter(s => s.health === "healthy").length}</b></div><div><i className="amber-bg" /><span>Cảnh báo<small>Cần theo dõi</small></span><b>{servers.filter(s => s.health === "warning").length}</b></div><div><i className="red-bg" /><span>Nguy cấp / Offline<small>Cần xử lý ngay</small></span><b>{servers.filter(s => ["critical", "offline"].includes(s.health)).length}</b></div></div></div></article>
              <article className="panel activity-panel"><div className="panel-head"><div><h2>Hoạt động gần đây</h2><p>Dữ liệu audit từ PostgreSQL</p></div><button onClick={() => setActive("audit")}>Mở nhật ký →</button></div><div className="overview-empty"><span>≡</span><b>Xem nhật ký kiểm toán</b><p>Các sự kiện thật được ghi vào chuỗi audit trong database, không hiển thị dữ liệu minh họa.</p><button className="button ghost" onClick={() => setActive("audit")}>Xem sự kiện</button></div></article>
            </section>
          </>}

          {active === "sessions" ? <SessionsView token={token} /> : active === "jobs" ? <JobsView token={token} /> : active === "audit" ? <AuditView token={token} /> : active === "access" ? <AccessView token={token} /> : <section className="panel fleet-panel"><div className="panel-head fleet-head"><div><h2>{scope ? `Danh sách ${scope === "linux" ? "Linux" : "Windows"}` : "Toàn bộ máy chủ"}</h2><p>{visibleServers.length} máy chủ · dữ liệu agent theo thời gian thực</p></div><div className="filters"><button className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>Tất cả</button><button className={filter === "healthy" ? "active" : ""} onClick={() => setFilter("healthy")}>Ổn định</button><button className={filter === "warning" ? "active" : ""} onClick={() => setFilter("warning")}>Cảnh báo</button><button className={filter === "critical" ? "active" : ""} onClick={() => setFilter("critical")}>Nguy cấp</button></div></div>{loading ? <div className="loading-line" /> : null}<ServerTable servers={visibleServers} onSelect={setSelected} /></section>}
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

function SystemUnavailable({ message }: { message: string }) {
  return <div className="login-page"><div className="login-glow" /><section className="system-unavailable"><span className="setup-state-icon">!</span><p className="login-eyebrow">CONTROL PLANE OFFLINE</p><h1>Không thể kiểm tra cấu hình</h1><p>{message}. Hãy kiểm tra API control plane rồi tải lại trang.</p><button className="button primary" onClick={() => window.location.reload()}>Thử lại</button></section></div>;
}

function SetupScreen({ status, onComplete }: { status: SetupStatus; onComplete: (dashboardUrl: string) => void }) {
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
    const dashboardUrl = String(form.get("dashboard_url") ?? "").replace(/\/$/, "");
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
      if (!response.ok) throw new Error(data.detail ?? "Không thể hoàn tất thiết lập");
      onComplete(data.dashboardUrl ?? dashboardUrl);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể hoàn tất thiết lập");
    } finally {
      setBusy(false);
    }
  }

  return <main className="setup-page">
    <div className="setup-orbit" />
    <header className="setup-header"><div className="login-brand"><span className="brand-mark">V</span><div><b>TRẠM</b><small>VẬN HÀNH</small></div></div><span className="setup-badge"><i /> THIẾT LẬP LẦN ĐẦU</span></header>
    <div className="setup-layout">
      <aside className="setup-intro">
        <p className="login-eyebrow">SECURE CONTROL PLANE</p>
        <h1>Khởi tạo trung tâm vận hành</h1>
        <p>Kết nối PostgreSQL, tạo quản trị viên local đầu tiên và xác lập địa chỉ chính thức cho dashboard.</p>
        <ol className="setup-steps">
          <li className="active"><span>01</span><div><b>PostgreSQL</b><small>Kết nối và khởi tạo schema</small></div></li>
          <li className="active"><span>02</span><div><b>Quản trị viên</b><small>Tài khoản local toàn quyền đầu tiên</small></div></li>
          <li className="active"><span>03</span><div><b>Địa chỉ dashboard</b><small>URL chuẩn dùng bởi agent và gateway</small></div></li>
        </ol>
        <div className="setup-note"><span>◆</span><p><b>Dữ liệu tập trung trong PostgreSQL</b><small>Tài khoản, máy chủ, tác vụ, cấu hình và audit được lưu bền vững. Khóa mã hóa được giữ tách biệt trong volume bảo mật.</small></p></div>
      </aside>

      <form className="setup-card" onSubmit={submit}>
        <div className="setup-card-head"><div><p className="login-eyebrow">BƯỚC KHỞI TẠO</p><h2>Cấu hình hệ thống</h2></div><div className={`connection-state ${status.databaseConnected ? "connected" : ""}`}><i />{status.databaseConnected ? "Đã kết nối" : "Chưa kết nối DB"}</div></div>

        <fieldset><legend><span>01</span><div><b>Kết nối PostgreSQL</b><small>Database cần tồn tại và tài khoản phải có quyền tạo bảng.</small></div></legend><div className="postgres-help"><b>Thông tin bản test dùng PostgreSQL trong Docker</b><span>Máy chủ: <code>postgres</code> · Cổng: <code>5432</code> · Database: <code>tramops</code> · Tài khoản: <code>tramops</code> · SSL: <code>Ưu tiên SSL</code></span><small>Mật khẩu là giá trị POSTGRES_PASSWORD trong file /home/ubuntu/dashboard-mgmt/.env trên server.</small></div><div className="setup-grid three"><label>Máy chủ<input name="db_host" defaultValue="postgres" required placeholder="postgres.example.internal" autoComplete="off" /></label><label>Cổng<input name="db_port" type="number" min="1" max="65535" defaultValue="5432" required /></label><label>SSL<select name="db_sslmode" defaultValue="prefer"><option value="prefer">Ưu tiên SSL</option><option value="require">Bắt buộc SSL</option><option value="verify-ca">Xác minh CA</option><option value="verify-full">Xác minh đầy đủ</option><option value="disable">Tắt SSL</option></select></label></div><div className="setup-grid"><label>Tên database<input name="db_name" defaultValue="tramops" required autoComplete="off" /></label><label>Tài khoản database<input name="db_username" defaultValue="tramops" required autoComplete="username" /></label></div><label>Mật khẩu database<input name="db_password" type="password" required autoComplete="current-password" /></label></fieldset>

        <fieldset><legend><span>02</span><div><b>Admin local đầu tiên</b><small>Dùng để đăng nhập khi chưa tích hợp hệ thống định danh doanh nghiệp.</small></div></legend><div className="setup-grid"><label>Tên đăng nhập<input name="admin_username" defaultValue="admin" minLength={3} pattern="[A-Za-z0-9_.@-]+" required autoComplete="username" /></label><label>Tên hiển thị<input name="admin_display_name" defaultValue="Platform Administrator" required /></label></div><div className="setup-grid"><label>Mật khẩu<input name="admin_password" type="password" minLength={14} required autoComplete="new-password" placeholder="Tối thiểu 14 ký tự" /></label><label>Nhập lại mật khẩu<input name="admin_password_confirm" type="password" minLength={14} required autoComplete="new-password" /></label></div></fieldset>

        <fieldset><legend><span>03</span><div><b>Địa chỉ dashboard</b><small>URL HTTP mà người dùng có thể truy cập.</small></div></legend><label>Dashboard URL<input name="dashboard_url" type="url" defaultValue={typeof window !== "undefined" ? window.location.origin : "http://ops.example.com"} required placeholder="http://ops.example.com" /></label>{status.setupTokenRequired && <label>Mã thiết lập<input name="setup_token" type="password" required autoComplete="one-time-code" /><small className="field-hint">Giá trị SETUP_TOKEN do người triển khai cung cấp.</small></label>}</fieldset>

        {error && <div className="setup-error"><span>!</span><p><b>Chưa thể hoàn tất thiết lập</b><small>{error}</small></p></div>}
        <div className="setup-actions"><p><span>◆</span> Mật khẩu database không được gửi về trình duyệt sau khi lưu.</p><button className="button primary" disabled={busy}>{busy ? "Đang kiểm tra và khởi tạo…" : "Kiểm tra kết nối & hoàn tất"}</button></div>
      </form>
    </div>
  </main>;
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

function SessionsView({ token }: { token: string }) {
  const [items, setItems] = useState<Array<{ id: string; serverName: string; protocol: string; username: string; createdBy: string; status: string; startedAt: string }>>([]);
  useEffect(() => { fetch("/api/v1/sessions", { headers: { Authorization: `Bearer ${token}` } }).then((response) => response.ok ? response.json() : Promise.reject()).then((data) => setItems(data.items ?? [])).catch(() => setItems([])); }, [token]);
  return <section className="panel view-panel"><div className="panel-head"><div><h2>Lịch sử phiên truy cập</h2><p>Mọi phiên được lưu trong PostgreSQL và gắn với danh tính người vận hành.</p></div><span className="live-pill"><i />{items.filter((item) => item.status === "launched").length} đã khởi tạo</span></div><div className="session-list">{items.length ? items.map((item) => <article key={item.id}><span className={`session-protocol ${item.protocol}`}>{item.protocol.toUpperCase()}</span><div><b>{item.serverName}</b><small>{item.username} · {item.createdBy}</small></div><time>{new Date(item.startedAt).toLocaleString("vi-VN")}</time><span className="recording">● CÓ GHI</span><span /></article>) : <div className="empty-state">Chưa có phiên truy cập nào trong database.</div>}</div></section>;
}

function JobsView({ token }: { token: string }) {
  const [jobs, setJobs] = useState<Array<{ id: string; serverId: string; action: string; status: string; risk: string; reason: string; createdAt: string }>>([]);
  useEffect(() => { fetch("/api/v1/jobs", { headers: { Authorization: `Bearer ${token}` } }).then((response) => response.ok ? response.json() : Promise.reject()).then((data) => setJobs(data.items ?? [])).catch(() => setJobs([])); }, [token]);
  const statusLabel = (status: string) => ({ pending_approval: "Chờ phê duyệt", queued: "Đang chờ agent", dispatched: "Đang chạy", succeeded: "Hoàn tất", failed: "Thất bại" }[status] ?? status);
  return <section className="panel view-panel"><div className="panel-head"><div><h2>Luồng công việc</h2><p>Tác vụ có cấu trúc, kiểm soát phê duyệt và lưu trong PostgreSQL.</p></div></div><div className="jobs-table"><div className="jobs-row head"><span>Công việc</span><span>Máy chủ</span><span>Mức rủi ro</span><span>Thời điểm</span><span>Trạng thái</span></div>{jobs.length ? jobs.map((job) => <div className="jobs-row" key={job.id}><p><b>{job.action}</b><small>{job.reason}</small></p><span>{job.serverId.slice(0, 8)}</span><span>{job.risk}</span><time>{new Date(job.createdAt).toLocaleString("vi-VN")}</time><span className={`job-state ${job.status === "succeeded" ? "done" : ["queued", "dispatched"].includes(job.status) ? "running" : "pending"}`}>{statusLabel(job.status)}</span></div>) : <div className="empty-state">Chưa có công việc nào trong database.</div>}</div></section>;
}

function AuditView({ token }: { token: string }) {
  const [rows, setRows] = useState<Array<{ id: string; occurredAt: string; actor: string; action: string; target: string; result: string; sourceIp: string }>>([]);
  const [forbidden, setForbidden] = useState(false);
  useEffect(() => { fetch("/api/v1/audit", { headers: { Authorization: `Bearer ${token}` } }).then((response) => { if (response.status === 403) setForbidden(true); return response.ok ? response.json() : Promise.reject(); }).then((data) => setRows(data.items ?? [])).catch(() => setRows([])); }, [token]);
  return <section className="panel view-panel"><div className="panel-head"><div><h2>Nhật ký bất biến</h2><p>Chuỗi sự kiện có hash liên kết và được lưu trong PostgreSQL.</p></div><div className="audit-integrity">◆ Chuỗi hash liên kết</div></div><div className="audit-table"><div className="audit-row head"><span>Thời gian</span><span>Chủ thể</span><span>Hành động</span><span>Đối tượng</span><span>Kết quả</span><span>IP nguồn</span></div>{rows.length ? rows.map((row) => <div className="audit-row" key={row.id}><time>{new Date(row.occurredAt).toLocaleString("vi-VN")}</time><b>{row.actor}</b><code>{row.action}</code><span>{row.target}</span><span className={row.result === "success" ? "result-good" : "result-warn"}>{row.result}</span><span>{row.sourceIp || "—"}</span></div>) : <div className="empty-state">{forbidden ? "Vai trò hiện tại không có quyền đọc audit." : "Chưa có sự kiện audit trong database."}</div>}</div></section>;
}

function AccessView({ token }: { token: string }) {
  const [users, setUsers] = useState<Array<{ id: string; username: string; displayName: string; role: string; enabled: boolean; createdAt: string }>>([]);
  const [forbidden, setForbidden] = useState(false);
  useEffect(() => { fetch("/api/v1/users", { headers: { Authorization: `Bearer ${token}` } }).then((response) => { if (response.status === 403) setForbidden(true); return response.ok ? response.json() : Promise.reject(); }).then((data) => setUsers(data.items ?? [])).catch(() => setUsers([])); }, [token]);
  return <div className="access-grid"><section className="panel view-panel"><div className="panel-head"><div><h2>Người dùng local</h2><p>Tài khoản và vai trò được đọc trực tiếp từ PostgreSQL.</p></div></div><div className="role-list">{users.length ? users.map((user) => <article key={user.id}><span>{user.role.slice(0, 2).toUpperCase()}</span><p><b>{user.displayName || user.username}</b><small>{user.username} · tạo {new Date(user.createdAt).toLocaleDateString("vi-VN")}</small></p><em>{user.enabled ? user.role : "đã khóa"}</em></article>) : <div className="empty-state">{forbidden ? "Chỉ admin được xem danh sách người dùng." : "Chưa có người dùng trong database."}</div>}</div></section><aside className="panel policy-panel"><h2>Vai trò hệ thống</h2><div className="policy-summary"><b>admin</b><small>Toàn quyền quản trị và phê duyệt.</small></div><div className="policy-summary"><b>operator</b><small>Vận hành máy chủ và mở phiên.</small></div><div className="policy-summary"><b>viewer</b><small>Đọc dữ liệu và chạy tác vụ an toàn.</small></div><div className="policy-summary"><b>auditor</b><small>Đọc audit và lịch sử phiên.</small></div></aside></div>;
}

function JobModal({ close, notify, servers, token }: { close: () => void; notify: (message: string) => void; servers: Server[]; token: string }) {
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const form = new FormData(event.currentTarget); try { const response = await fetch("/api/v1/jobs", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ server_id: form.get("server_id"), action: form.get("action"), parameters: {}, reason: form.get("reason"), require_approval: true }) }); const data = await response.json(); if (!response.ok) throw new Error(data.detail ?? "Không thể tạo công việc"); close(); notify(`Đã tạo công việc ${data.id.slice(0, 8)} · ${data.status}.`); } catch (reason) { notify(reason instanceof Error ? reason.message : "Không thể tạo công việc"); } }
  return <div className="modal-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại" onClick={close} /><form className="modal" onSubmit={submit}><div className="modal-head"><div><span className="modal-icon">▶</span><div><h2>Tạo công việc</h2><p>Thực thi qua agent với audit đầy đủ</p></div></div><button type="button" onClick={close}>×</button></div><label>Máy chủ<select name="server_id" required defaultValue=""><option value="" disabled>Chọn máy chủ…</option>{servers.map((server) => <option key={server.id} value={server.id}>{server.name} · {server.os}</option>)}</select></label><label>Hành động<select name="action"><option value="inventory.collect">Thu thập inventory</option><option value="patch.scan">Liệt kê bản vá</option><option value="patch.install_security">Cài bản vá bảo mật</option><option value="service.list">Liệt kê dịch vụ</option><option value="process.list">Liệt kê tiến trình</option><option value="firewall.list">Xem firewall</option><option value="system.reboot">Khởi động lại máy chủ</option></select></label><label>Lý do thay đổi<textarea name="reason" required placeholder="Mã ticket, mục đích và ảnh hưởng dự kiến…" rows={3} /></label><label className="check"><input type="checkbox" defaultChecked /> Yêu cầu phê duyệt trước khi chạy</label><div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button primary">Tạo công việc</button></div></form></div>;
}

function SessionModal({ close, notify, server, token }: { close: () => void; notify: (message: string) => void; server: Server; token: string }) {
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const form = new FormData(event.currentTarget); const protocol = server.osFamily === "windows" ? "rdp" : "ssh"; const sessionWindow = window.open("about:blank", "_blank"); if (sessionWindow) sessionWindow.opener = null; try { const response = await fetch("/api/v1/sessions/launch", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ server_id: server.id, protocol, username: form.get("username"), password: form.get("password") }) }); const data = await response.json(); if (!response.ok) throw new Error(data.detail ?? "Không thể tạo phiên"); close(); if (sessionWindow) sessionWindow.location.href = data.url; else window.location.href = data.url; notify(`Đã tạo phiên ${protocol.toUpperCase()} có ghi lại.`); } catch (reason) { sessionWindow?.close(); notify(reason instanceof Error ? reason.message : "Không thể tạo phiên"); } }
  return <div className="modal-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng hộp thoại" onClick={close} /><form className="modal" onSubmit={submit}><div className="modal-head"><div><span className="modal-icon">↗</span><div><h2>{server.osFamily === "windows" ? "Remote Desktop" : "Phiên SSH"}</h2><p>{server.name} · phiên được ghi lại</p></div></div><button type="button" onClick={close}>×</button></div><label>Tên đăng nhập<input name="username" required autoComplete="username" placeholder={server.osFamily === "linux" ? "Ví dụ: ubuntu" : undefined} /></label><label>Mật khẩu phiên<input type="password" name="password" required autoComplete="current-password" /></label><div className="warning-box"><b>{server.osFamily === "linux" ? "Không dùng root trên Ubuntu mặc định" : "Thông tin xác thực dùng một lần"}</b><p>{server.osFamily === "linux" ? "Dùng tài khoản thường đã đặt mật khẩu, ví dụ ubuntu. Có thể đặt bằng lệnh: sudo passwd ubuntu." : "Mật khẩu chỉ được đưa vào token Guacamole mã hóa, không được lưu trong database hoặc audit log."}</p></div><div className="modal-actions"><button type="button" className="button ghost" onClick={close}>Hủy</button><button className="button primary">Mở phiên & bắt đầu ghi</button></div></form></div>;
}

function CommandPalette({ close, servers, select }: { close: () => void; servers: Server[]; select: (server: Server) => void }) {
  const [value, setValue] = useState("");
  const matches = servers.filter((s) => `${s.name} ${s.address}`.includes(value.toLowerCase())).slice(0, 5);
  return <div className="modal-backdrop command-backdrop"><button className="modal-dismiss" type="button" aria-label="Đóng bảng lệnh" onClick={close} /><div className="command-palette"><div className="command-input"><span>⌕</span><input aria-label="Tìm máy chủ hoặc hành động" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Tìm máy chủ hoặc hành động…" /><kbd>ESC</kbd></div><p>MÁY CHỦ</p>{matches.map((server) => <button key={server.id} onClick={() => select(server)}><span className={`os-avatar ${server.osFamily}`}>{server.osFamily === "windows" ? "W" : ">_"}</span><span><b>{server.name}</b><small>{server.address} · {server.os}</small></span><em>↵</em></button>)}</div></div>;
}
