"use client";

import Guacamole from "guacamole-common-js";
import { DragEvent, FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

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
  tunnelOnline: boolean;
};

const navItems = [
  { id: "overview", icon: "⌂", label: "Tổng quan" },
  { id: "linux", icon: "L", label: "Máy chủ Linux", count: 3 },
  { id: "windows", icon: "W", label: "Máy chủ Windows", count: 3 },
  { id: "sessions", icon: "↗", label: "Phiên truy cập" },
  { id: "jobs", icon: "▶", label: "Công việc" },
  { id: "audit", icon: "≡", label: "Nhật ký kiểm toán" },
  { id: "access", icon: "◎", label: "Người dùng & vai trò" },
  { id: "agents", icon: "↓", label: "Bộ cài Agent" },
];

const healthLabel: Record<Health, string> = {
  healthy: "Ổn định",
  warning: "Cảnh báo",
  critical: "Nguy cấp",
  offline: "Mất kết nối",
};

function serverRoute(server: Server) {
  return `#/${server.osFamily}/${encodeURIComponent(server.name)}`;
}

function sectionRoute(section: string) {
  return `#/${section}`;
}

function parseServiceOutput(output: string | undefined) {
  if (!output) return [];
  try {
    const parsed = JSON.parse(output) as unknown;
    const rows = Array.isArray(parsed) ? parsed : [parsed];
    return rows
      .filter((row): row is Record<string, unknown> => Boolean(row) && typeof row === "object")
      .map((row) => ({
        name: String(row.Name ?? row.name ?? ""),
        displayName: String(row.DisplayName ?? row.displayName ?? "—"),
        status: String(row.Status ?? row.status ?? row.state ?? "chưa rõ"),
        startType: String(row.StartType ?? row.startType ?? "—"),
      }))
      .filter((row) => row.name);
  } catch {
    return output
      .split(/\r?\n/)
      .map((line) => line.match(/^\s*(?:●\s*)?(\S+\.service)\s+\S+\s+(\S+)\s+(\S+)\s*(.*)$/))
      .filter((match): match is RegExpMatchArray => Boolean(match))
      .map((match) => ({
        name: match[1],
        displayName: match[4] || "—",
        status: match[3],
        startType: "—",
      }));
  }
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
    const applyHashRoute = () => {
      const [section, encodedName] = window.location.hash.replace(/^#\/?/, "").split("/");
      if (section === "linux" || section === "windows") {
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
      } else if (navItems.some((item) => item.id === section)) {
        setActive(section);
        setSelected(null);
      }
    };
    applyHashRoute();
    window.addEventListener("hashchange", applyHashRoute);
    window.addEventListener("popstate", applyHashRoute);
    return () => {
      window.removeEventListener("hashchange", applyHashRoute);
      window.removeEventListener("popstate", applyHashRoute);
    };
  }, [servers]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setModal("command");
      }
      if (event.key === "Escape") {
        setModal(null);
        setSelected(null);
        if (active === "linux" || active === "windows")
          window.history.pushState(null, "", sectionRoute(active));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active]);

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

  function openServer(server: Server) {
    setActive(server.osFamily);
    setSelected(server);
    const route = serverRoute(server);
    if (window.location.hash !== route) window.history.pushState(null, "", route);
  }

  function navigateSection(section: string) {
    setActive(section);
    setSelected(null);
    window.history.pushState(null, "", sectionRoute(section));
  }

  function closeServer() {
    const section = selected?.osFamily ?? (active === "windows" ? "windows" : "linux");
    setSelected(null);
    window.history.pushState(null, "", sectionRoute(section));
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
          onClick={() => navigateSection("overview")}
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
                onClick={() => navigateSection(item.id)}
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
                onClick={() => navigateSection(item.id)}
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
              onClick={() => navigateSection(item.id)}
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
          {!selected && <div className="page-head">
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
          </div>}

          {!selected && active === "overview" && (
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
                    <button onClick={() => navigateSection("audit")}>
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
                      onClick={() => navigateSection("audit")}
                    >
                      Xem sự kiện
                    </button>
                  </div>
                </article>
              </section>
            </>
          )}

          {selected ? (
            <ServerDrawer
              server={selected}
              close={closeServer}
              openSession={() => setModal("session")}
              notify={notify}
              token={token}
            />
          ) : active === "sessions" ? (
            <SessionsView token={token} />
          ) : active === "jobs" ? (
            <JobsView token={token} />
          ) : active === "audit" ? (
            <AuditView token={token} />
          ) : active === "access" ? (
            <AccessView token={token} />
          ) : active === "agents" ? (
            <AgentPackagesView token={token} />
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
              <ServerTable servers={visibleServers} onSelect={openServer} />
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
  { id: "services", label: "Dịch vụ", icon: "◉" },
  { id: "accounts", label: "Tài khoản", icon: "◎" },
  { id: "firewall", label: "Firewall", icon: "◇" },
  { id: "processes", label: "Tiến trình", icon: "▤" },
  { id: "updates", label: "Cập nhật", icon: "↥" },
  { id: "files", label: "Truyền file", icon: "↳" },
  { id: "logs", label: "Nhật ký", icon: "≡" },
];

const actionOptions: Partial<Record<ServerTab, Array<{ value: string; label: string }>>> = {
  accounts: [
    { value: "user.create", label: "Tạo user" },
    { value: "user.password.reset", label: "Đặt lại mật khẩu" },
    { value: "user.disable", label: "Khóa user" },
    { value: "user.enable", label: "Mở khóa user" },
    { value: "user.delete", label: "Xóa user" },
    { value: "group.create", label: "Tạo group" },
    { value: "group.delete", label: "Xóa group" },
    { value: "user.add_group", label: "Thêm user vào group" },
    { value: "group.remove_user", label: "Xóa user khỏi group" },
  ],
  services: [
    { value: "service.restart", label: "Khởi động lại service" },
    { value: "service.start", label: "Bật service" },
    { value: "service.stop", label: "Dừng service" },
  ],
  storage: [{ value: "storage.extend", label: "Mở rộng ổ/Logical Volume" }],
  updates: [
    { value: "patch.install_security", label: "Cài bản vá bảo mật" },
    { value: "system.reboot", label: "Khởi động lại máy chủ" },
  ],
};

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
        LogicalVolumes?: Array<{ lv_path?: string }>;
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
  const [action, setAction] = useState("user.create");
  const [busy, setBusy] = useState(false);
  const [firewallModal, setFirewallModal] = useState<"add" | "delete" | "reorder" | null>(null);
  const [selectedFirewallRules, setSelectedFirewallRules] = useState<string[]>([]);
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
  useEffect(() => {
    void loadDetail();
    void loadTransfers();
    void loadJobs();
    const timer = window.setInterval(() => void loadJobs(), 5_000);
    return () => window.clearInterval(timer);
  }, [loadDetail, loadTransfers, loadJobs]);
  const facts = detail?.inventory?.extra;
  const groups = (facts?.Groups ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  const users = (facts?.Users ?? [])
    .map((item) => item.name ?? item.Name ?? "")
    .filter(Boolean);
  const storage = facts?.Storage ?? [];
  const logicalVolumes = facts?.LogicalVolumes ?? [];
  const serviceFacts = facts?.Services ?? [];
  const services = serviceFacts.map((item) => item.name ?? item.Name ?? "").filter(Boolean);
  const currentReadAction = readActionByTab[activeTab];
  const latestReadJob = currentReadAction
    ? jobs.find((job) => job.action === currentReadAction)
    : undefined;
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
  const selectedRules = firewallRules.filter((rule) =>
    selectedFirewallRules.includes(firewallRuleKey(rule)),
  );
  const removableRules = firewallRules.filter((rule) => rule.removable !== false);
  const refreshedServices =
    activeTab === "services" && latestReadJob?.status === "succeeded"
      ? parseServiceOutput(latestReadJob.output)
      : [];
  const serviceRows = refreshedServices.length
    ? refreshedServices
    : serviceFacts.map((service, index) => ({
        name: service.name ?? service.Name ?? `service-${index + 1}`,
        displayName: service.DisplayName ?? "—",
        status: service.Status ?? "chưa tải",
        startType: service.StartType ?? service.state ?? "—",
      }));
  async function queueJob(
    nextAction: string,
    parameters: Record<string, unknown>,
    reason: string,
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
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Không thể tạo tác vụ");
    notify(`Đã gửi tác vụ ${nextAction} tới Agent · ${data.status}.`);
    await loadJobs();
    return data as { id: string; status: string; risk: string };
  }
  async function refreshCurrentTab(parameters: Record<string, unknown> = {}) {
    if (!currentReadAction) return;
    setBusy(true);
    try {
      await queueJob(
        currentReadAction,
        parameters,
        `Đọc dữ liệu ${activeTab} từ ${server.name}`,
      );
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : "Không thể yêu cầu dữ liệu mới");
    } finally {
      setBusy(false);
    }
  }
  function selectTab(tab: ServerTab) {
    setActiveTab(tab);
    const options = actionOptions[tab] ?? [];
    if (options.length) setAction(options[0].value);
    if (tab === "firewall" && (!latestFirewallJob || latestFirewallJob.status === "failed"))
      void queueJob("firewall.list", {}, `Quét firewall rules trên ${server.name}`).catch((reason) =>
        notify(reason instanceof Error ? reason.message : "Không thể quét firewall"),
      );
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
    setFileBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch(`/api/v1/servers/${server.id}/files`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(data.detail ?? "Không thể tải file vào vùng cách ly");
      notify("File sạch đã được xếp hàng để Agent nhận và chuyển vào inbox cách ly.");
      event.currentTarget.reset();
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
          <button className="connect" onClick={openSession} disabled={!server.tunnelOnline}>
            <span>↗</span>
            <b>{server.osFamily === "windows" ? "Remote Desktop" : "Mở SSH"}</b>
            <small>
              {server.tunnelOnline ? "Tunnel mTLS 9443 sẵn sàng" : "Tunnel agent đang offline"}
            </small>
          </button>
          <button
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
                v{server.agentVersion} · mTLS · {server.tunnelOnline ? "tunnel online" : "tunnel offline"}
              </dd>
            </div>
          </dl>
            </>
          )}

          {activeTab !== "overview" && activeTab !== "files" && (
            <>
              <div className="server-tab-toolbar">
                <div>
                  <h2>{serverTabs.find((tab) => tab.id === activeTab)?.label}</h2>
                  <p>Dữ liệu thật từ Agent và lịch sử tác vụ trong PostgreSQL.</p>
                </div>
                {currentReadAction && activeTab !== "firewall" && (
                  <button className="button ghost" onClick={() => void refreshCurrentTab()} disabled={busy}>
                    {busy ? "Đang yêu cầu…" : "↻ Lấy dữ liệu mới"}
                  </button>
                )}
                {activeTab === "firewall" && (
                  <div className="firewall-toolbar-actions">
                    <button className="button ghost" onClick={() => void refreshCurrentTab()} disabled={busy}>
                      {busy ? "Đang quét…" : "↻ Quét lại"}
                    </button>
                    <button className="firewall-icon-button add" type="button" aria-label="Thêm firewall rule" title="Thêm firewall rule" onClick={() => setFirewallModal("add")}>+</button>
                    <button className="firewall-icon-button remove" type="button" aria-label="Xóa firewall rule đã chọn" title="Xóa firewall rule đã chọn" disabled={selectedRules.length === 0} onClick={() => { setFirewallConfirmation(""); setFirewallModal("delete"); }}>−</button>
                  </div>
                )}
              </div>

              {activeTab === "storage" && (
                <div className="inventory-table">
                  <div className="inventory-row head"><span>Ổ / thiết bị</span><span>Filesystem</span><span>Dung lượng</span><span>Còn trống</span></div>
                  {storage.length ? storage.map((volume, index) => {
                    const name = volume.DriveLetter ?? volume.path ?? volume.Path ?? volume.name ?? `volume-${index + 1}`;
                    const size = Number(volume.Size ?? volume.size ?? 0);
                    const remaining = Number(volume.SizeRemaining ?? 0);
                    return (
                      <div className="inventory-row" key={`${name}-${index}`}>
                        <b>{name}{volume.DriveLetter ? ":" : ""}</b>
                        <span>{volume.FileSystem ?? volume.fstype ?? "—"}</span>
                        <span>{size ? `${(size / 1024 ** 3).toFixed(1)} GB` : "—"}</span>
                        <span>{remaining ? `${(remaining / 1024 ** 3).toFixed(1)} GB` : "—"}</span>
                      </div>
                    );
                  }) : <div className="empty-state">Chưa có dữ liệu ổ đĩa trong inventory.</div>}
                </div>
              )}

              {activeTab === "services" && (
                <div className="inventory-table services-table">
                  <div className="inventory-row head"><span>Service</span><span>Tên hiển thị</span><span>Trạng thái</span><span>Khởi động</span></div>
                  {serviceRows.length ? serviceRows.slice(0, 250).map((service, index) => {
                    return (
                      <div className="inventory-row" key={`${service.name}-${index}`}>
                        <b>{service.name}</b>
                        <span>{service.displayName}</span>
                        <span className={`service-state ${String(service.status).toLowerCase()}`}>{service.status}</span>
                        <span>{service.startType}</span>
                      </div>
                    );
                  }) : <div className="empty-state">Chưa có danh sách dịch vụ; nhấn “Lấy dữ liệu mới”.</div>}
                </div>
              )}

              {activeTab === "accounts" && (
                <div className="account-columns">
                  <section>
                    <h3>Tài khoản local ({users.length})</h3>
                    <div className="compact-list">{(facts?.Users ?? []).map((user, index) => <div key={`${user.name ?? user.Name}-${index}`}><b>{user.name ?? user.Name}</b><span>{user.Enabled === false ? "Đã khóa" : user.shell ?? user.home ?? "Hoạt động"}</span></div>)}</div>
                  </section>
                  <section>
                    <h3>Nhóm local ({groups.length})</h3>
                    <div className="compact-list">{(facts?.Groups ?? []).map((group, index) => <div key={`${group.name ?? group.Name}-${index}`}><b>{group.name ?? group.Name}</b><span>{(group.members ?? group.Members ?? []).slice(0, 4).join(", ") || "Không có thành viên trực tiếp"}</span></div>)}</div>
                  </section>
                </div>
              )}

              {activeTab === "firewall" && (
                <section className="firewall-rule-panel">
                  <div className="firewall-rule-summary">
                    <span><b>{firewallRules.length}</b> rule · backend <strong>{firewallScan.backend || "chưa xác định"}</strong></span>
                    <span>{selectedRules.length} rule đang chọn</span>
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
                        {firewallRules.map((rule) => {
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
                                if (source?.orderGroup === rule.orderGroup && source.id !== rule.id && rule.reorderable === true) {
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
                    {latestReadJob?.status === "succeeded" && firewallScan.warning && <div className="firewall-scan-warning"><b>Agent {server.agentVersion || "chưa rõ phiên bản"}</b><span>{firewallScan.warning}</span></div>}
                  </div>
                  <p className="firewall-note">Rule mới được xếp hàng ngay và chèn đầu chain UFW/nftables/iptables; sau mọi kết quả thêm, xóa hoặc đổi thứ tự, hệ thống tự quét lại danh sách thật từ Agent. Agent vẫn từ chối nếu zone/chain hoặc snapshot đã cũ. Windows Firewall không hỗ trợ thứ tự do quản trị viên gán: Block xung đột vẫn ưu tiên hơn Allow. Firewalld dùng priority và các chain hành động riêng nên chưa cho kéo để tránh tạo cảm giác sai về thứ tự thực thi.</p>
                </section>
              )}

              {activeTab === "updates" && (
                <div className="update-summary-card">
                  <strong>{server.updates}</strong>
                  <span>Bản cập nhật đang chờ</span>
                  <p>Cài bản vá bảo mật và reboot được xếp hàng trực tiếp, có RBAC và audit.</p>
                </div>
              )}

              {latestReadJob && activeTab !== "firewall" && (
                <section className="operation-result">
                  <header>
                    <b>{latestReadJob.action}</b>
                    <span className={`job-state ${latestReadJob.status}`}>{latestReadJob.status}</span>
                    <time>{new Date(latestReadJob.createdAt).toLocaleString("vi-VN")}</time>
                  </header>
                  {latestReadJob.output ? <pre>{latestReadJob.output}</pre> : <p>Agent sẽ trả kết quả ở lần check-in tiếp theo.</p>}
                </section>
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
                File tối đa 50 MiB, được quét ClamAV trước khi mã hóa lưu trong PostgreSQL,
                sau đó được xếp hàng trực tiếp và quét lại bằng Defender/ClamAV tại máy đích. Agent
                không tự chạy file và không ghi đè file đã có.
              </p>
            </div>
            <button className="button primary" disabled={fileBusy || !server.tunnelOnline}>
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

          {(actionOptions[activeTab]?.length ?? 0) > 0 && (
            <>
          <h3>Thao tác trên {server.name}</h3>
          <form className="server-action-form" onSubmit={submitAction}>
            <label>
              Loại tác vụ
              <select
                value={action}
                onChange={(event) => setAction(event.target.value)}
              >
                {(actionOptions[activeTab] ?? []).map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
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
            </>
          )}
        </div>
      </section>
      {firewallModal === "add" && (
        <FirewallAddModal
          key={`${server.id}:${latestFirewallJob?.id ?? "no-scan"}:${latestFirewallJob?.status ?? "pending"}`}
          server={server}
          scan={firewallScan}
          busy={busy}
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
  const backendDescription = {
    windows: "Profile được Agent đọc bằng Get-NetFirewallProfile trên đúng Windows Server này.",
    ufw: "UFW tự ánh xạ Inbound/Outbound sang chain phù hợp; không cần nhập table hoặc chain.",
    firewalld: "public là zone của firewalld, không phải chain. Danh sách zone bên dưới lấy trực tiếp từ máy chủ.",
    nftables: "Chỉ base chain loại filter có hook INPUT/OUTPUT lấy từ nftables được phép chọn; chain NAT/DOCKER bị loại.",
    iptables: "INPUT/OUTPUT là chain. UI chỉ cho chọn chain filter đang tồn tại do Agent báo về.",
  }[backend] ?? "Đang chờ Agent quét backend firewall và trả metadata từ máy chủ.";
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
      exitCode?: number | null;
      output?: string;
    }>
  >([]);
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
  return (
    <section className="panel view-panel">
      <div className="panel-head">
        <div>
          <h2>Luồng công việc</h2>
          <p>
            Tác vụ được kiểm tra theo allowlist, xếp hàng trực tiếp và lưu audit trong PostgreSQL.
          </p>
        </div>
      </div>
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
              </div>
              {job.status === "failed" && (
                <pre className="job-error-output">Exit code {job.exitCode ?? "?"}{"\n"}{job.output || "Agent không trả về nội dung lỗi."}</pre>
              )}
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

function AgentPackagesView({ token }: { token: string }) {
  const [status, setStatus] = useState<{
    dashboardUrl: string;
    agentVersion: string;
    linuxAvailable: boolean;
    windowsMsiAvailable: boolean;
    agentTlsCaAvailable: boolean;
    claimTtlMinutes: number;
    webTlsTrust: "internal-ca" | "system";
  } | null>(null);
  const [busy, setBusy] = useState<OSFamily | null>(null);
  const [message, setMessage] = useState("");
  const [messageIsError, setMessageIsError] = useState(false);

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
      setMessage(data.detail ?? "Không thể cập nhật URL control plane");
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
          : "Đã tạo gói Linux dùng một lần. Chạy: chmod +x <file>.run && sudo ./<file>.run",
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
        <h2>Bộ cài tự nhận đúng control plane</h2>
        <p>
          Domain, chế độ xác minh TLS và claim một lần được lấy từ cấu hình HTTPS của hệ thống.
          Private key mTLS chỉ được sinh trên máy đích, không nằm trong file tải về.
        </p>
        <form className="package-origin" key={status?.dashboardUrl} onSubmit={saveDashboardUrl}>
          <span>URL control plane dùng để sinh Agent</span>
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
          <small>Hãy mở dashboard bằng chính domain mới, hoàn tất DNS/TLS/Nginx/Caddy rồi mới lưu.</small>
        </form>
        <ul>
          <li>Claim hết hạn sau tối đa 60 phút và chỉ dùng được một lần.</li>
          <li>
            Bootstrap web: {status?.webTlsTrust === "system" ? "CA công khai của Nginx" : "CA nội bộ đã pin"};
            agent mTLS trên 9443 vẫn dùng CA riêng.
          </li>
          <li>Windows MSI cài service LocalSystem, tự khởi động cùng Windows và tự restart khi lỗi.</li>
          <li>Linux cài systemd service, tự enroll và khởi động ngay sau khi cài.</li>
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
            <p>Agent {status?.agentVersion ?? "…"} · chỉ admin được tạo claim enrollment.</p>
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
        <div className="agent-package-options">
          <button
            className="package-option linux"
            type="submit"
            data-os="linux"
            disabled={busy !== null || status?.linuxAvailable === false || status?.agentTlsCaAvailable === false}
          >
            <span>L</span>
            <b>Tải Linux .run</b>
            <small>Ubuntu 24.04 · Oracle Linux 7/8</small>
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
        {busy && <p className="package-progress">Đang sinh claim và đóng gói {busy}…</p>}
        {status && !status.windowsMsiAvailable && (
          <p className="package-warning">MSI chung chưa có trong API image. Build workflow Windows rồi rebuild container API.</p>
        )}
        {status && !status.agentTlsCaAvailable && (
          <p className="package-warning">
            CA TLS của kênh Agent chưa được đồng bộ. Kiểm tra container caddy-ca-export rồi recreate API trước khi tải bộ cài.
          </p>
        )}
        {message && <p className={`settings-message${messageIsError ? " error" : ""}`}>{message}</p>}
        <div className="package-security-note">
          Không đổi tên MSI Windows: tên file chứa locator và chế độ xác minh TLS. Không gửi bộ cài qua kênh công cộng và không tái sử dụng file sau khi một máy đã claim.
        </div>
      </form>
    </section>
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
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
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
      // Guacamole persists its own token across tabs in origin-wide
      // localStorage. A stale token from a previous/manual Guacamole login
      // takes precedence over the encrypted JSON connection in the new URL,
      // causing the valid temporary connection to appear missing. Dashboard
      // authentication uses a separate sessionStorage key and is unaffected.
      window.localStorage.removeItem("GUAC_AUTH_TOKEN");
      if (sessionWindow) sessionWindow.location.href = data.url;
      else window.location.href = data.url;
      notify(
        `Đã tạo phiên ${protocol.toUpperCase()} có ghi lại ở độ phân giải ${width}×${height}.`,
      );
    } catch (reason) {
      sessionWindow?.close();
      notify(reason instanceof Error ? reason.message : "Không thể tạo phiên");
    } finally {
      setBusy(false);
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
              ? "Control plane sẽ buộc Agent kết nối thành công tới 127.0.0.1:22 trước khi mở Guacamole. Dùng tài khoản thường đã đặt mật khẩu, ví dụ ubuntu."
              : "Mật khẩu chỉ được đưa vào token Guacamole mã hóa, không được lưu trong database hoặc audit log."}
          </p>
        </div>
        <div className="modal-actions">
          <button type="button" className="button ghost" onClick={close}>
            Hủy
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? "Đang kiểm tra tunnel và dịch vụ local…" : "Mở phiên & bắt đầu ghi"}
          </button>
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
