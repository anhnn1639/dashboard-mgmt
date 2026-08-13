"use client";

import Guacamole from "guacamole-common-js";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

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

const healthLabel: Record<Health, string> = {
  healthy: "Ổn định",
  warning: "Cảnh báo",
  critical: "Nguy cấp",
  offline: "Mất kết nối",
};

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
}: {
  servers: Server[];
  onSelect: (server: Server) => void;
}) {
  return (
    <div className="table-scroll">
      <table className="server-table">
        <thead>
          <tr>
            <th>Máy chủ</th>
            <th>Hệ điều hành</th>
            <th>Trạng thái</th>
            <th>CPU</th>
            <th>Bộ nhớ</th>
            <th>Ổ đĩa</th>
            <th>Cập nhật</th>
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
              <td>
                <div className="server-name">
                  <span className={`os-avatar ${server.osFamily}`}>
                    {server.osFamily === "windows" ? "W" : ">_"}
                  </span>
                  <span>
                    <strong>{server.name}</strong>
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
              <td>
                <button
                  className="row-more"
                  aria-label={`Mở ${server.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelect(server);
                  }}
                >
                  •••
                </button>
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
  const [active, setActive] = useState("overview");
  const [selected, setSelected] = useState<Server | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | Health>("all");
  const [modal, setModal] = useState<"command" | "session" | null>(null);
  const [toast, setToast] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetch("/api/v1/setup/status", { headers: { Accept: "application/json" } })
      .then((response) =>
        response.ok
          ? response.json()
          : Promise.reject(new Error("Control plane chưa sẵn sàng")),
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
      setToken(window.sessionStorage.getItem("tram_ops_token") ?? "");
      setAuthReady(true);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!token) return;
    let mounted = true;
    const loadServers = () =>
      fetch("/api/v1/servers", {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
        },
      })
        .then((response) => {
          if (response.status === 401) {
            window.sessionStorage.removeItem("tram_ops_token");
            setToken("");
            throw new Error("Unauthorized");
          }
          return response.ok
            ? response.json()
            : Promise.reject(new Error("Unable to load servers"));
        })
        .then((data) => {
          if (mounted && Array.isArray(data.items)) setServers(data.items);
        })
        .catch(() => undefined)
        .finally(() => {
          if (mounted) setLoading(false);
        });
    void loadServers();
    const timer = window.setInterval(() => {
      void loadServers();
    }, 15_000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [token]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setModal("command");
      }
      if (event.key === "Escape") {
        setModal(null);
        setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const scope = active === "linux" || active === "windows" ? active : null;
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

  const title =
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
                : "Trung tâm vận hành";

  if (setupStatusError) return <SystemUnavailable message={setupStatusError} />;
  if (!setupStatus || !authReady)
    return <div className="auth-loading">Đang kiểm tra cấu hình hệ thống…</div>;
  if (setupStatus.setupRequired)
    return (
      <SetupScreen
        status={setupStatus}
        onComplete={(dashboardUrl) => {
          window.sessionStorage.removeItem("tram_ops_token");
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
        onLogin={(nextToken) => {
          window.sessionStorage.setItem("tram_ops_token", nextToken);
          setToken(nextToken);
        }}
      />
    );

  return (
    <main className="shell">
      <aside className="sidebar">
        <button
          className="brand"
          onClick={() => setActive("overview")}
          aria-label="Về tổng quan"
        >
          <span className="brand-mark">V</span>
          <span>
            <b>TRẠM</b>
            <small>VẬN HÀNH</small>
          </span>
        </button>
        <nav aria-label="Điều hướng chính">
          <p className="nav-heading">HẠ TẦNG</p>
          {navItems.slice(0, 3).map((item) => {
            const count = navCount(item.id, item.count);
            return (
              <button
                key={item.id}
                className={active === item.id ? "active" : ""}
                onClick={() => {
                  setActive(item.id);
                  setSelected(null);
                }}
              >
                <span className="nav-icon">{item.icon}</span>
                {item.label}
                {count !== undefined && <em>{count}</em>}
              </button>
            );
          })}
          <p className="nav-heading spaced">VẬN HÀNH</p>
          {navItems.slice(3, 6).map((item) => {
            const count = navCount(item.id, item.count);
            return (
              <button
                key={item.id}
                className={active === item.id ? "active" : ""}
                onClick={() => {
                  setActive(item.id);
                  setSelected(null);
                }}
              >
                <span className="nav-icon">{item.icon}</span>
                {item.label}
                {count !== undefined && <em>{count}</em>}
              </button>
            );
          })}
          <p className="nav-heading spaced">QUẢN TRỊ</p>
          {navItems.slice(6).map((item) => (
            <button
              key={item.id}
              className={active === item.id ? "active" : ""}
              onClick={() => {
                setActive(item.id);
                setSelected(null);
              }}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="security-card">
          <div className="security-title">
            <span>◆</span>
            <b>Kết nối được bảo vệ</b>
          </div>
          <p>Agent mTLS · TLS 1.3</p>
          <div>
            <i />
            CA nội bộ hoạt động
          </div>
        </div>
        <button
          className="profile"
          onClick={() => {
            window.sessionStorage.removeItem("tram_ops_token");
            setToken("");
          }}
          title="Đăng xuất"
        >
          <span className="profile-avatar">AD</span>
          <span>
            <b>Administrator</b>
            <small>Nhấn để đăng xuất</small>
          </span>
          <strong>⌄</strong>
        </button>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="search">
            <span>⌕</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Tìm máy chủ, IP hoặc nhãn..."
              aria-label="Tìm kiếm"
            />
            <kbd>Ctrl K</kbd>
            {searchMatches.length > 0 && (
              <div className="search-suggestions">
                {searchMatches.map((server) => (
                  <button
                    key={server.id}
                    onClick={() => {
                      setSelected(server);
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
            <button className="icon-button" aria-label="Thông báo">
              ♢<span className="notification-dot" />
            </button>
            <button className="help">?</button>
            <span className="now">
              <i />
              Hệ thống ổn định
            </span>
          </div>
        </header>

        <div className="content">
          <div className="page-head">
            <div>
              <p className="eyebrow">CONTROL PLANE · AP-SOUTHEAST</p>
              <h1>{title}</h1>
              <p>
                Giám sát, truy cập và thực thi tác vụ an toàn trên toàn bộ máy
                chủ.
              </p>
            </div>
            <div className="head-actions">
              <button
                className="button ghost"
                onClick={() => window.location.reload()}
              >
                ↻ Làm mới
              </button>
            </div>
          </div>

          {active === "overview" && (
            <>
              <section className="stat-grid" aria-label="Tóm tắt hạ tầng">
                <article className="stat-card">
                  <div className="stat-top">
                    <span className="stat-icon blue">▦</span>
                    <span className="delta good">PostgreSQL</span>
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
                    <span className="delta">7 ngày</span>
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
                      <p>Trạng thái 24 giờ gần nhất</p>
                    </div>
                    <button>24 giờ⌄</button>
                  </div>
                  <div className="health-chart">
                    <div
                      className="donut"
                      style={
                        {
                          "--healthy": `${availability * 3.6}deg`,
                        } as React.CSSProperties
                      }
                    >
                      <span>
                        <b>{availability}%</b>
                        <small>khả dụng</small>
                      </span>
                    </div>
                    <div className="health-legend">
                      <div>
                        <i className="green-bg" />
                        <span>
                          Ổn định
                          <small>
                            {
                              servers.filter((s) => s.health === "healthy")
                                .length
                            }{" "}
                            máy chủ
                          </small>
                        </span>
                        <b>
                          {servers.filter((s) => s.health === "healthy").length}
                        </b>
                      </div>
                      <div>
                        <i className="amber-bg" />
                        <span>
                          Cảnh báo<small>Cần theo dõi</small>
                        </span>
                        <b>
                          {servers.filter((s) => s.health === "warning").length}
                        </b>
                      </div>
                      <div>
                        <i className="red-bg" />
                        <span>
                          Nguy cấp / Offline<small>Cần xử lý ngay</small>
                        </span>
                        <b>
                          {
                            servers.filter((s) =>
                              ["critical", "offline"].includes(s.health),
                            ).length
                          }
                        </b>
                      </div>
                    </div>
                  </div>
                </article>
                <article className="panel activity-panel">
                  <div className="panel-head">
                    <div>
                      <h2>Hoạt động gần đây</h2>
                      <p>Dữ liệu audit từ PostgreSQL</p>
                    </div>
                    <button onClick={() => setActive("audit")}>
                      Mở nhật ký →
                    </button>
                  </div>
                  <div className="overview-empty">
                    <span>≡</span>
                    <b>Xem nhật ký kiểm toán</b>
                    <p>
                      Các sự kiện thật được ghi vào chuỗi audit trong database,
                      không hiển thị dữ liệu minh họa.
                    </p>
                    <button
                      className="button ghost"
                      onClick={() => setActive("audit")}
                    >
                      Xem sự kiện
                    </button>
                  </div>
                </article>
              </section>
            </>
          )}

          {active === "sessions" ? (
            <SessionsView token={token} />
          ) : active === "jobs" ? (
            <JobsView token={token} />
          ) : active === "audit" ? (
            <AuditView token={token} />
          ) : active === "access" ? (
            <AccessView token={token} />
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
              {loading ? <div className="loading-line" /> : null}
              <ServerTable servers={visibleServers} onSelect={setSelected} />
            </section>
          )}
        </div>
      </section>

      {selected && (
        <ServerDrawer
          server={selected}
          close={() => setSelected(null)}
          openSession={() => setModal("session")}
          notify={notify}
          token={token}
        />
      )}
      {modal === "session" && selected && (
        <SessionModal
          close={() => setModal(null)}
          notify={notify}
          server={selected}
          token={token}
        />
      )}
      {modal === "command" && (
        <CommandPalette
          close={() => setModal(null)}
          servers={servers}
          select={(server) => {
            setSelected(server);
            setModal(null);
          }}
        />
      )}
      {toast && (
        <div className="toast">
          <span>✓</span>
          {toast}
        </div>
      )}
    </main>
  );
}

function SystemUnavailable({ message }: { message: string }) {
  return (
    <div className="login-page">
      <div className="login-glow" />
      <section className="system-unavailable">
        <span className="setup-state-icon">!</span>
        <p className="login-eyebrow">CONTROL PLANE OFFLINE</p>
        <h1>Không thể kiểm tra cấu hình</h1>
        <p>{message}. Hãy kiểm tra API control plane rồi tải lại trang.</p>
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
          <span className="brand-mark">V</span>
          <div>
            <b>TRẠM</b>
            <small>VẬN HÀNH</small>
          </div>
        </div>
        <span className="setup-badge">
          <i /> THIẾT LẬP LẦN ĐẦU
        </span>
      </header>
      <div className="setup-layout">
        <aside className="setup-intro">
          <p className="login-eyebrow">SECURE CONTROL PLANE</p>
          <h1>Khởi tạo trung tâm vận hành</h1>
          <p>
            Kết nối PostgreSQL, tạo quản trị viên local đầu tiên và xác lập địa
            chỉ chính thức cho dashboard.
          </p>
          <ol className="setup-steps">
            <li className="active">
              <span>01</span>
              <div>
                <b>PostgreSQL</b>
                <small>Kết nối và khởi tạo schema</small>
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
                <b>Địa chỉ dashboard</b>
                <small>URL chuẩn dùng bởi agent và gateway</small>
              </div>
            </li>
          </ol>
          <div className="setup-note">
            <span>◆</span>
            <p>
              <b>Dữ liệu tập trung trong PostgreSQL</b>
              <small>
                Tài khoản, máy chủ, tác vụ, cấu hình và audit được lưu bền vững.
                Khóa mã hóa được giữ tách biệt trong volume bảo mật.
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
              {status.databaseConnected ? "Đã kết nối" : "Chưa kết nối DB"}
            </div>
          </div>

          <fieldset>
            <legend>
              <span>01</span>
              <div>
                <b>Kết nối PostgreSQL</b>
                <small>
                  Database cần tồn tại và tài khoản phải có quyền tạo bảng.
                </small>
              </div>
            </legend>
            <div className="postgres-help">
              <b>Thông tin bản test dùng PostgreSQL trong Docker</b>
              <span>
                Máy chủ: <code>postgres</code> · Cổng: <code>5432</code> ·
                Database: <code>tramops</code> · Tài khoản: <code>tramops</code>{" "}
                · SSL: <code>Ưu tiên SSL</code>
              </span>
              <small>
                Mật khẩu là giá trị POSTGRES_PASSWORD trong file
                /home/ubuntu/dashboard-mgmt/.env trên server.
              </small>
            </div>
            <div className="setup-grid three">
              <label>
                Máy chủ
                <input
                  name="db_host"
                  defaultValue="postgres"
                  required
                  placeholder="postgres.example.internal"
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
                  defaultValue="5432"
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
                Tên database
                <input
                  name="db_name"
                  defaultValue="tramops"
                  required
                  autoComplete="off"
                />
              </label>
              <label>
                Tài khoản database
                <input
                  name="db_username"
                  defaultValue="tramops"
                  required
                  autoComplete="username"
                />
              </label>
            </div>
            <label>
              Mật khẩu database
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
                <small>URL HTTP mà người dùng có thể truy cập.</small>
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
                    : "http://ops.example.com"
                }
                required
                placeholder="http://ops.example.com"
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
              <span>◆</span> Mật khẩu database không được gửi về trình duyệt sau
              khi lưu.
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

function LoginScreen({ onLogin }: { onLogin: (token: string) => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"local" | "domain">("local");
  const [mfa, setMfa] = useState<{
    challenge_token: string;
    setup_required: boolean;
    qr_svg?: string;
    provisioning_uri?: string;
  } | null>(null);
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
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/auth/mfa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge_token: mfa.challenge_token,
          code: form.get("code"),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Mã MFA không hợp lệ");
      onLogin(data.access_token);
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
        <form className="login-card mfa-card" onSubmit={verifyMfa}>
          <div className="login-brand">
            <span className="brand-mark">V</span>
            <div>
              <b>TRẠM</b>
              <small>MFA BẮT BUỘC</small>
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
            <object
              className="mfa-qr"
              data={mfa.qr_svg}
              type="image/svg+xml"
              aria-label="QR thiết lập MFA"
            />
          )}
          <label>
            Mã MFA 6 số
            <input
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
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
          <span className="brand-mark">V</span>
          <div>
            <b>TRẠM</b>
            <small>VẬN HÀNH</small>
          </div>
        </div>
        <p className="login-eyebrow">SECURE CONTROL PLANE</p>
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
            ? "Tài khoản quản trị được lưu trong PostgreSQL."
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

function ServerDrawer({
  server,
  close,
  openSession,
  notify,
  token,
}: {
  server: Server;
  close: () => void;
  openSession: () => void;
  notify: (message: string) => void;
  token: string;
}) {
  type Fact = {
    name?: string;
    Name?: string;
    members?: string[];
    Members?: string[];
    path?: string;
    Path?: string;
    DriveLetter?: string;
  };
  type Detail = {
    inventory?: {
      extra?: {
        Users?: Fact[];
        Groups?: Fact[];
        Storage?: Fact[];
        LogicalVolumes?: Array<{ lv_path?: string }>;
        Services?: Fact[];
      };
    };
  };
  const [detail, setDetail] = useState<Detail | null>(null);
  const [action, setAction] = useState("user.create");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    fetch(`/api/v1/servers/${server.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then(setDetail)
      .catch(() => setDetail(null));
  }, [server.id, token]);
  const facts = detail?.inventory?.extra;
  const groups = (facts?.Groups ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  const users = (facts?.Users ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  const storage = facts?.Storage ?? [];
  const logicalVolumes = facts?.LogicalVolumes ?? [];
  const services = (facts?.Services ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  async function queueJob(
    nextAction: string,
    parameters: Record<string, unknown>,
    reason: string,
    requireApproval = true,
  ) {
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
        require_approval: requireApproval,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Không thể tạo tác vụ");
    notify(`Đã tạo tác vụ ${nextAction} · ${data.status}.`);
  }
  async function submitAction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const parameters: Record<string, unknown> = {};
    for (const [key, value] of form.entries())
      if (key !== "reason" && value !== "") parameters[key] = value;
    if (action === "user.create")
      parameters.groups = form.get("group") ? [form.get("group")] : [];
    if (parameters.port) parameters.port = Number(parameters.port);
    if (parameters.size_gb) parameters.size_gb = Number(parameters.size_gb);
    try {
      await queueJob(
        action,
        parameters,
        String(form.get("reason") ?? "Thao tác từ máy chủ đã chọn"),
      );
      event.currentTarget.reset();
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể tạo tác vụ");
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <button
        className="drawer-scrim"
        onClick={close}
        aria-label="Đóng chi tiết"
      />
      <aside className="drawer management-drawer">
        <div className="drawer-top">
          <button onClick={close}>×</button>
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
          <button className="connect" onClick={openSession}>
            <span>↗</span>
            <b>{server.osFamily === "windows" ? "Remote Desktop" : "Mở SSH"}</b>
            <small>Qua gateway bảo mật</small>
          </button>
          <button
            onClick={() =>
              queueJob(
                "inventory.collect",
                {},
                "Làm mới dữ liệu máy chủ",
                false,
              ).catch((reason) => notify(reason.message))
            }
          >
            <span>↻</span>
            <b>Làm mới</b>
            <small>Đồng bộ agent</small>
          </button>
        </div>
        <div className="drawer-body">
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
              <dd>v{server.agentVersion} · mTLS</dd>
            </div>
          </dl>
          <h3>Thao tác trên {server.name}</h3>
          <form className="server-action-form" onSubmit={submitAction}>
            <label>
              Loại tác vụ
              <select
                value={action}
                onChange={(event) => setAction(event.target.value)}
              >
                <option value="user.create">Tạo user</option>
                <option value="user.password.reset">Đặt lại mật khẩu</option>
                <option value="user.disable">Khóa user</option>
                <option value="user.enable">Mở khóa user</option>
                <option value="user.delete">Xóa user</option>
                <option value="group.create">Tạo group</option>
                <option value="group.delete">Xóa group</option>
                <option value="user.add_group">Thêm user vào group</option>
                <option value="group.remove_user">Xóa user khỏi group</option>
                <option value="service.restart">Khởi động lại service</option>
                <option value="service.start">Bật service</option>
                <option value="service.stop">Dừng service</option>
                <option value="firewall.rule.add">Thêm rule firewall</option>
                <option value="firewall.rule.remove">Xóa rule firewall</option>
                <option value="storage.extend">Mở rộng ổ/Logical Volume</option>
                <option value="patch.install_security">
                  Cài bản vá bảo mật
                </option>
                <option value="system.reboot">Khởi động lại</option>
              </select>
            </label>
            {action === "user.create" && (
              <>
                <label>
                  Tên user
                  <input name="username" required pattern="[A-Za-z0-9._-]+" />
                </label>
                <label>
                  Mật khẩu ban đầu
                  <input
                    name="password"
                    type="password"
                    minLength={12}
                    required
                  />
                </label>
                <label>
                  Group trên máy chủ
                  <select name="group">
                    <option value="">Chọn group…</option>
                    {groups.map((group) => (
                      <option key={group}>{group}</option>
                    ))}
                  </select>
                </label>
              </>
            )}
            {action === "group.create" && (
              <label>
                Tên group
                <input name="group" required pattern="[A-Za-z0-9._-]+" />
              </label>
            )}
            {[
              "user.password.reset",
              "user.disable",
              "user.enable",
              "user.delete",
            ].includes(action) && (
              <>
                <label>
                  User trên máy chủ
                  <select name="username" required>
                    <option value="">Chọn user…</option>
                    {users.map((user) => (
                      <option key={user}>{user}</option>
                    ))}
                  </select>
                </label>
                {action === "user.password.reset" && (
                  <label>
                    Mật khẩu mới
                    <input
                      name="password"
                      type="password"
                      minLength={12}
                      required
                    />
                  </label>
                )}
              </>
            )}
            {action === "group.delete" && (
              <label>
                Group trên máy chủ
                <select name="group" required>
                  <option value="">Chọn group…</option>
                  {groups.map((group) => (
                    <option key={group}>{group}</option>
                  ))}
                </select>
              </label>
            )}
            {["user.add_group", "group.remove_user"].includes(action) && (
              <>
                <label>
                  User
                  <select name="username" required>
                    <option value="">Chọn user…</option>
                    {users.map((user) => (
                      <option key={user}>{user}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Group
                  <select name="group" required>
                    <option value="">Chọn group…</option>
                    {groups.map((group) => (
                      <option key={group}>{group}</option>
                    ))}
                  </select>
                </label>
              </>
            )}
            {["service.restart", "service.start", "service.stop"].includes(
              action,
            ) && (
              <label>
                Service trên máy chủ
                <select name="name" required>
                  <option value="">Chọn service…</option>
                  {services.map((service) => (
                    <option key={service}>{service}</option>
                  ))}
                </select>
              </label>
            )}
            {action.startsWith("firewall.rule") && (
              <>
                <label>
                  Tên rule
                  <input name="name" required pattern="[A-Za-z0-9._-]+" />
                </label>
                <div className="form-grid">
                  <label>
                    Cổng
                    <input
                      name="port"
                      type="number"
                      min="1"
                      max="65535"
                      required
                    />
                  </label>
                  <label>
                    Protocol
                    <select name="protocol">
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </label>
                </div>
                <div className="form-grid">
                  <label>
                    Hành động
                    <select name="action">
                      <option value="allow">Allow</option>
                      <option value="deny">Deny/Block</option>
                    </select>
                  </label>
                  <label>
                    Nguồn
                    <input
                      name="source"
                      defaultValue="any"
                      placeholder="any hoặc CIDR"
                    />
                  </label>
                </div>
              </>
            )}
            {action === "storage.extend" &&
              (server.osFamily === "windows" ? (
                <label>
                  Ổ Windows
                  <select name="drive" required>
                    <option value="">Chọn ổ…</option>
                    {storage.map((volume, index) => {
                      const drive =
                        volume.DriveLetter ?? volume.path ?? volume.Path ?? "";
                      return drive ? (
                        <option key={`${drive}-${index}`} value={drive}>
                          {drive}:
                        </option>
                      ) : null;
                    })}
                  </select>
                </label>
              ) : (
                <>
                  <label>
                    Logical Volume trên máy chủ
                    <select name="logical_volume" required>
                      <option value="">Chọn Logical Volume…</option>
                      {logicalVolumes.map((volume) =>
                        volume.lv_path ? (
                          <option key={volume.lv_path} value={volume.lv_path}>
                            {volume.lv_path}
                          </option>
                        ) : null,
                      )}
                    </select>
                  </label>
                  <label>
                    Dung lượng thêm (GB)
                    <input
                      name="size_gb"
                      type="number"
                      min="1"
                      max="10240"
                      required
                    />
                  </label>
                </>
              ))}
            <label>
              Lý do / ticket
              <textarea
                name="reason"
                required
                rows={2}
                placeholder="CHG-1234 · Mô tả thay đổi"
              />
            </label>
            <button className="button primary" disabled={busy}>
              {busy ? "Đang gửi…" : "Gửi tác vụ có kiểm soát"}
            </button>
          </form>
        </div>
      </aside>
    </>
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
            Mọi phiên được lưu trong PostgreSQL và gắn với danh tính người vận
            hành.
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
            Chưa có phiên truy cập nào trong database.
          </div>
        )}
      </div>
    </section>
  );
}

function JobsView({ token }: { token: string }) {
  const [jobs, setJobs] = useState<
    Array<{
      id: string;
      serverId: string;
      action: string;
      status: string;
      risk: string;
      reason: string;
      createdAt: string;
    }>
  >([]);
  const [message, setMessage] = useState("");
  useEffect(() => {
    fetch("/api/v1/jobs", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((data) => setJobs(data.items ?? []))
      .catch(() => setJobs([]));
  }, [token]);
  async function approve(jobId: string) {
    const response = await fetch(`/api/v1/jobs/${jobId}/approve`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) {
      setMessage(data.detail ?? "Không thể phê duyệt tác vụ");
      return;
    }
    setJobs((current) =>
      current.map((job) =>
        job.id === jobId ? { ...job, status: data.status } : job,
      ),
    );
    setMessage("Đã phê duyệt; agent sẽ nhận tác vụ ở lần check-in tiếp theo.");
  }
  const statusLabel = (status: string) =>
    ({
      pending_approval: "Chờ phê duyệt",
      queued: "Đang chờ agent",
      dispatched: "Đang chạy",
      succeeded: "Hoàn tất",
      failed: "Thất bại",
    })[status] ?? status;
  return (
    <section className="panel view-panel">
      <div className="panel-head">
        <div>
          <h2>Luồng công việc</h2>
          <p>
            Tác vụ có cấu trúc, kiểm soát phê duyệt và lưu trong PostgreSQL.
          </p>
        </div>
      </div>
      {message && <p className="settings-message">{message}</p>}
      <div className="jobs-table">
        <div className="jobs-row head">
          <span>Công việc</span>
          <span>Máy chủ</span>
          <span>Mức rủi ro</span>
          <span>Thời điểm</span>
          <span>Trạng thái</span>
        </div>
        {jobs.length ? (
          jobs.map((job) => (
            <div className="jobs-row" key={job.id}>
              <p>
                <b>{job.action}</b>
                <small>{job.reason}</small>
              </p>
              <span>{job.serverId.slice(0, 8)}</span>
              <span>{job.risk}</span>
              <time>{new Date(job.createdAt).toLocaleString("vi-VN")}</time>
              <div className="job-controls">
                <span
                  className={`job-state ${job.status === "succeeded" ? "done" : ["queued", "dispatched"].includes(job.status) ? "running" : "pending"}`}
                >
                  {statusLabel(job.status)}
                </span>
                {job.status === "pending_approval" && (
                  <button onClick={() => approve(job.id)}>Phê duyệt</button>
                )}
              </div>
            </div>
          ))
        ) : (
          <div className="empty-state">
            Chưa có công việc nào trong database.
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
  startedAt: string;
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
    }>
  >([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [forbidden, setForbidden] = useState(false);
  const [tab, setTab] = useState<"events" | "recordings">("events");
  const [selectedRecording, setSelectedRecording] =
    useState<SessionRecord | null>(null);
  useEffect(() => {
    fetch("/api/v1/audit", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => {
        if (response.status === 403) setForbidden(true);
        return response.ok ? response.json() : Promise.reject();
      })
      .then((data) => setRows(data.items ?? []))
      .catch(() => setRows([]));
    fetch("/api/v1/sessions", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((data) => setSessions(data.items ?? []))
      .catch(() => setSessions([]));
  }, [token]);
  return (
    <>
      <section className="panel view-panel">
        <div className="panel-head">
          <div>
            <h2>Nhật ký kiểm toán</h2>
            <p>Sự kiện và recording phiên truy cập được quản lý tập trung.</p>
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
          <button
            className={tab === "recordings" ? "active" : ""}
            onClick={() => setTab("recordings")}
          >
            Video ghi session
          </button>
        </div>
        {tab === "events" ? (
          <div className="audit-table">
            <div className="audit-row head">
              <span>Thời gian</span>
              <span>Chủ thể</span>
              <span>Hành động</span>
              <span>Đối tượng</span>
              <span>Kết quả</span>
              <span>IP nguồn</span>
            </div>
            {rows.length ? (
              rows.map((row) => (
                <div className="audit-row" key={row.id}>
                  <time>
                    {new Date(row.occurredAt).toLocaleString("vi-VN")}
                  </time>
                  <b>{row.actor}</b>
                  <code>{row.action}</code>
                  <span>{row.target}</span>
                  <span
                    className={
                      row.result === "success" ? "result-good" : "result-warn"
                    }
                  >
                    {row.result}
                  </span>
                  <span>{row.sourceIp || "—"}</span>
                </div>
              ))
            ) : (
              <div className="empty-state">
                {forbidden
                  ? "Vai trò hiện tại không có quyền đọc audit."
                  : "Chưa có sự kiện audit trong database."}
              </div>
            )}
          </div>
        ) : (
          <div className="recording-list audit-recordings">
            {sessions.length ? (
              sessions.map((session) => (
                <div key={session.id}>
                  <span className="play">▶</span>
                  <p>
                    <b>
                      {session.serverName} · {session.protocol.toUpperCase()}
                    </b>
                    <small>
                      {session.username} · {session.createdBy} ·{" "}
                      {new Date(session.startedAt).toLocaleString("vi-VN")}
                    </small>
                  </p>
                  <span
                    className={
                      session.recordingAvailable
                        ? "verified"
                        : "recording-pending"
                    }
                  >
                    {session.recordingAvailable
                      ? "● Sẵn sàng"
                      : "Đang chờ file"}
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
        )}
      </section>
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

function AccessView({ token }: { token: string }) {
  const [users, setUsers] = useState<
    Array<{
      id: string;
      username: string;
      displayName: string;
      role: string;
      enabled: boolean;
      createdAt: string;
    }>
  >([]);
  const [forbidden, setForbidden] = useState(false);
  const [ldap, setLdap] = useState<Record<string, string | number | boolean>>({
    enabled: false,
    port: 636,
    use_ssl: true,
    user_attribute: "sAMAccountName",
    display_attribute: "displayName",
    domain_label: "DOMAIN",
    default_role: "viewer",
  });
  const [message, setMessage] = useState("");
  useEffect(() => {
    fetch("/api/v1/users", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => {
        if (response.status === 403) setForbidden(true);
        return response.ok ? response.json() : Promise.reject();
      })
      .then((data) => setUsers(data.items ?? []))
      .catch(() => setUsers([]));
    fetch("/api/v1/settings/ldap", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((data) => setLdap((current) => ({ ...current, ...data })))
      .catch(() => undefined);
  }, [token]);
  async function saveLdap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = {
      enabled: form.get("enabled") === "on",
      host: form.get("host"),
      port: Number(form.get("port")),
      use_ssl: form.get("use_ssl") === "on",
      base_dn: form.get("base_dn"),
      bind_dn: form.get("bind_dn"),
      bind_password: form.get("bind_password"),
      ca_certificate: form.get("ca_certificate"),
      user_attribute: form.get("user_attribute"),
      display_attribute: form.get("display_attribute"),
      domain_label: form.get("domain_label"),
      default_role: form.get("default_role"),
    };
    const response = await fetch("/api/v1/settings/ldap", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    setMessage(
      response.ok
        ? "Đã lưu cấu hình LDAP."
        : (data.detail ?? "Không thể lưu LDAP"),
    );
    if (response.ok) setLdap((current) => ({ ...current, ...data }));
  }
  async function createLocalUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const response = await fetch("/api/v1/users", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ username: form.get("username"), display_name: form.get("display_name"), password: form.get("password"), role: form.get("role") }),
    });
    const data = await response.json();
    if (!response.ok) {
      setMessage(data.detail ?? "Không thể tạo tài khoản Local");
      return;
    }
    setUsers((current) => [...current, data].sort((a, b) => a.username.localeCompare(b.username)));
    setMessage("Đã tạo tài khoản Local. Người dùng sẽ phải quét MFA ở lần đăng nhập đầu tiên.");
    formElement.reset();
  }
  return (
    <div className="access-grid">
      <section className="panel view-panel">
        <div className="panel-head">
          <div>
            <h2>Người dùng Local & Domain</h2>
            <p>
              Danh tính đăng nhập thành công được lưu trong PostgreSQL và bắt
              buộc MFA.
            </p>
          </div>
        </div>
        <div className="role-list">
          {users.length ? (
            users.map((user) => (
              <article key={user.id}>
                <span>{user.role.slice(0, 2).toUpperCase()}</span>
                <p>
                  <b>{user.displayName || user.username}</b>
                  <small>
                    {user.username} · tạo{" "}
                    {new Date(user.createdAt).toLocaleDateString("vi-VN")}
                  </small>
                </p>
                <em>{user.enabled ? user.role : "đã khóa"}</em>
              </article>
            ))
          ) : (
            <div className="empty-state">
              {forbidden
                ? "Chỉ admin được xem danh sách người dùng."
                : "Chưa có người dùng trong database."}
            </div>
          )}
        </div>
      </section>
      <aside className="panel ldap-panel">
        <h2>Tạo tài khoản Local</h2>
        <form onSubmit={createLocalUser}>
          <div className="form-grid">
            <label>Tên đăng nhập<input name="username" required minLength={3} pattern="[A-Za-z0-9_.@-]+" /></label>
            <label>Vai trò<select name="role"><option value="admin">admin</option><option value="operator">operator</option><option value="viewer">viewer</option><option value="auditor">auditor</option></select></label>
          </div>
          <label>Tên hiển thị<input name="display_name" required /></label>
          <label>Mật khẩu ban đầu<input name="password" type="password" required minLength={14} /></label>
          <button className="button primary">Tạo user và bắt buộc MFA</button>
        </form>
        <hr />
        <h2>Kết nối LDAP / Active Directory</h2>
        <form key={JSON.stringify(ldap)} onSubmit={saveLdap}>
          <label className="check">
            <input
              name="enabled"
              type="checkbox"
              defaultChecked={Boolean(ldap.enabled)}
            />{" "}
            Bật Domain Login
          </label>
          <div className="form-grid">
            <label>
              LDAP Host
              <input
                name="host"
                required
                defaultValue={String(ldap.host ?? "")}
                placeholder="dc01.company.local"
              />
            </label>
            <label>
              Cổng
              <input
                name="port"
                type="number"
                defaultValue={Number(ldap.port ?? 636)}
              />
            </label>
          </div>
          <label className="check">
            <input
              name="use_ssl"
              type="checkbox"
              defaultChecked={Boolean(ldap.use_ssl)}
            />{" "}
            Dùng LDAPS và xác minh certificate
          </label>
          <label>
            Base DN
            <input
              name="base_dn"
              required
              defaultValue={String(ldap.base_dn ?? "")}
              placeholder="DC=company,DC=local"
            />
          </label>
          <label>
            Bind DN
            <input
              name="bind_dn"
              defaultValue={String(ldap.bind_dn ?? "")}
              placeholder="CN=svc-dashboard,OU=Service Accounts,..."
            />
          </label>
          <label>
            Bind password
            <input
              name="bind_password"
              type="password"
              placeholder={
                ldap.password_configured
                  ? "Đã lưu · để trống nếu giữ nguyên"
                  : "Mật khẩu service account"
              }
            />
          </label>
          <label>
            CA certificate cho LDAPS (tùy chọn)
            <textarea name="ca_certificate" rows={4} defaultValue={String(ldap.ca_certificate ?? "")} placeholder="-----BEGIN CERTIFICATE-----" />
          </label>
          <div className="form-grid">
            <label>
              Thuộc tính user
              <input
                name="user_attribute"
                defaultValue={String(ldap.user_attribute ?? "sAMAccountName")}
              />
            </label>
            <label>
              Thuộc tính tên
              <input
                name="display_attribute"
                defaultValue={String(ldap.display_attribute ?? "displayName")}
              />
            </label>
          </div>
          <div className="form-grid">
            <label>
              Nhãn domain
              <input
                name="domain_label"
                defaultValue={String(ldap.domain_label ?? "DOMAIN")}
              />
            </label>
            <label>
              Role mặc định
              <select
                name="default_role"
                defaultValue={String(ldap.default_role ?? "viewer")}
              >
                <option value="viewer">viewer</option>
                <option value="operator">operator</option>
                <option value="auditor">auditor</option>
              </select>
            </label>
          </div>
          {message && <p className="settings-message">{message}</p>}
          <button className="button primary">Lưu cấu hình LDAP</button>
        </form>
      </aside>
    </div>
  );
}

function SessionModal({
  close,
  notify,
  server,
  token,
}: {
  close: () => void;
  notify: (message: string) => void;
  server: Server;
  token: string;
}) {
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const protocol = server.osFamily === "windows" ? "rdp" : "ssh";
    const sessionWindow = window.open("about:blank", "_blank");
    if (sessionWindow) sessionWindow.opener = null;
    const pixelRatio = window.devicePixelRatio || 1;
    const width = Math.min(
      7680,
      Math.max(800, Math.round(window.screen.width * pixelRatio)),
    );
    const height = Math.min(
      4320,
      Math.max(600, Math.round(window.screen.height * pixelRatio)),
    );
    try {
      const response = await fetch("/api/v1/sessions/launch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          server_id: server.id,
          protocol,
          username: form.get("username"),
          password: form.get("password"),
          width,
          height,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không thể tạo phiên");
      close();
      if (sessionWindow) sessionWindow.location.href = data.url;
      else window.location.href = data.url;
      notify(
        `Đã tạo phiên ${protocol.toUpperCase()} có ghi lại ở độ phân giải ${width}×${height}.`,
      );
    } catch (reason) {
      sessionWindow?.close();
      notify(reason instanceof Error ? reason.message : "Không thể tạo phiên");
    }
  }
  return (
    <div className="modal-backdrop">
      <button
        className="modal-dismiss"
        type="button"
        aria-label="Đóng hộp thoại"
        onClick={close}
      />
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <div>
            <span className="modal-icon">↗</span>
            <div>
              <h2>
                {server.osFamily === "windows" ? "Remote Desktop" : "Phiên SSH"}
              </h2>
              <p>{server.name} · phiên được ghi lại</p>
            </div>
          </div>
          <button type="button" onClick={close}>
            ×
          </button>
        </div>
        <label>
          Tên đăng nhập
          <input
            name="username"
            required
            autoComplete="username"
            placeholder={
              server.osFamily === "linux" ? "Ví dụ: ubuntu" : undefined
            }
          />
        </label>
        <label>
          Mật khẩu phiên
          <input
            type="password"
            name="password"
            required
            autoComplete="current-password"
          />
        </label>
        <div className="warning-box">
          <b>
            {server.osFamily === "linux"
              ? "Không dùng root trên Ubuntu mặc định"
              : "Thông tin xác thực dùng một lần"}
          </b>
          <p>
            {server.osFamily === "linux"
              ? "Dùng tài khoản thường đã đặt mật khẩu, ví dụ ubuntu. Có thể đặt bằng lệnh: sudo passwd ubuntu."
              : "Mật khẩu chỉ được đưa vào token Guacamole mã hóa, không được lưu trong database hoặc audit log."}
          </p>
        </div>
        <div className="modal-actions">
          <button type="button" className="button ghost" onClick={close}>
            Hủy
          </button>
          <button className="button primary">Mở phiên & bắt đầu ghi</button>
        </div>
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
