"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { ModalShell } from "./server-resource-tabs";

type ServerOption = {
  id: string;
  name: string;
  address: string;
  osFamily: "linux" | "windows";
  os: string;
};

type UserOption = {
  id: string;
  username: string;
  displayName: string;
  role: string;
  source: "local" | "ldap";
  enabled: boolean;
};

type RemoteCredentialRow = {
  id: string;
  serverId: string;
  serverName: string;
  serverAddress: string;
  protocol: "ssh" | "rdp";
  label: string;
  username: string;
  userIds: string[];
  passwordConfigured: boolean;
  createdAt: string;
  updatedAt: string;
};

export function RemoteCredentialsView({ servers, token, notify }: { servers: ServerOption[]; token: string; notify: (message: string) => void }) {
  const [credentials, setCredentials] = useState<RemoteCredentialRow[]>([]);
  const [users, setUsers] = useState<UserOption[]>([]);
  const [editing, setEditing] = useState<RemoteCredentialRow | "new" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    const headers = { Authorization: `Bearer ${token}` };
    const [credentialResponse, userResponse] = await Promise.all([
      fetch("/api/v1/remote-credentials", { headers, cache: "no-store" }),
      fetch("/api/v1/users", { headers, cache: "no-store" }),
    ]);
    const credentialPayload = await credentialResponse.json();
    const userPayload = await userResponse.json();
    if (!credentialResponse.ok) throw new Error(credentialPayload.detail ?? "Không thể đọc tài khoản Remote");
    if (!userResponse.ok) throw new Error(userPayload.detail ?? "Không thể đọc người dùng");
    setCredentials(credentialPayload.items ?? []);
    setUsers(userPayload.items ?? []);
  }, [token]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load().catch((reason) => setError(reason instanceof Error ? reason.message : "Không thể tải dữ liệu"));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const shareableUsers = useMemo(() => users.filter((user) => user.enabled && user.role !== "admin"), [users]);
  const selected = editing === "new" ? null : editing;

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const serverId = selected?.serverId ?? String(form.get("server_id") ?? "");
    const server = servers.find((item) => item.id === serverId);
    if (!server) {
      setBusy(false);
      setError("Hãy chọn máy chủ");
      return;
    }
    const body: Record<string, unknown> = {
      label: form.get("label"),
      username: form.get("username"),
      password: form.get("password"),
      user_ids: form.getAll("user_ids"),
    };
    if (!selected) {
      body.server_id = server.id;
      body.protocol = server.osFamily === "windows" ? "rdp" : "ssh";
    }
    try {
      const response = await fetch(selected ? `/api/v1/remote-credentials/${selected.id}` : "/api/v1/remote-credentials", {
        method: selected ? "PUT" : "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Không thể lưu tài khoản Remote");
      setEditing(null);
      await load();
      notify(selected ? "Đã cập nhật tài khoản Remote." : "Đã tạo tài khoản Remote.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể lưu tài khoản Remote");
    } finally {
      setBusy(false);
    }
  }

  async function remove(item: RemoteCredentialRow) {
    if (!window.confirm(`Xóa tài khoản “${item.label}” khỏi ${item.serverName}?`)) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`/api/v1/remote-credentials/${item.id}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Không thể xóa tài khoản Remote");
      await load();
      notify("Đã xóa tài khoản Remote.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể xóa tài khoản Remote");
    } finally {
      setBusy(false);
    }
  }

  return <>
    <section className="panel remote-credentials-panel">
      <div className="panel-head remote-credentials-head">
        <div><h2>Tài khoản xác thực</h2><p>Chỉ Administrator quản lý. Người được share chỉ có thể chọn nhãn tài khoản để mở phiên.</p></div>
        <div className="resource-toolbar-actions"><button type="button" className="button ghost" disabled={busy} onClick={() => void load().catch((reason) => setError(reason instanceof Error ? reason.message : "Không thể tải dữ liệu"))}>↻ Làm mới</button><button type="button" className="button primary compact" onClick={() => setEditing("new")}>＋ Thêm tài khoản</button></div>
      </div>
      {error && <div className="danger-panel">{error}</div>}
      <div className="resource-help">Mật khẩu được mã hóa ở máy chủ Trạm vận hành, không trả về trình duyệt và không ghi vào nhật ký. Share máy chủ cho người dùng trước, sau đó mới share tài khoản Remote.</div>
      <div className="resource-table-scroll"><table className="resource-table"><thead><tr><th>Máy chủ</th><th>Giao thức</th><th>Nhãn tài khoản</th><th>Username</th><th>Được share</th><th /></tr></thead><tbody>{credentials.map((item) => <tr key={item.id}><td><b>{item.serverName}</b><small>{item.serverAddress}</small></td><td><span className="state-pill">{item.protocol.toUpperCase()}</span></td><td><b>{item.label}</b><small>{item.passwordConfigured ? "Đã lưu mật khẩu mã hóa" : "Chưa có mật khẩu"}</small></td><td>{item.username}</td><td>{item.userIds.length} người dùng</td><td><div className="row-actions"><button type="button" className="row-more" onClick={() => setEditing(item)}>Sửa</button><button type="button" className="button danger compact" disabled={busy} onClick={() => void remove(item)}>Xóa</button></div></td></tr>)}</tbody></table>{!credentials.length && <div className="empty-state">Chưa có tài khoản Remote. Hãy tạo tài khoản cho từng máy chủ cần truy cập.</div>}</div>
    </section>
    {editing && <ModalShell title={selected ? `Sửa ${selected.label}` : "Thêm tài khoản Remote"} subtitle="Mật khẩu chỉ được dùng phía máy chủ khi khởi tạo SSH/RDP" close={() => setEditing(null)}><form key={selected?.id ?? "new"} className="resource-form" onSubmit={save}>{error && <div className="danger-panel">{error}</div>}{!selected && <label>Máy chủ<select name="server_id" required defaultValue=""><option value="" disabled>Chọn máy chủ…</option>{servers.map((server) => <option key={server.id} value={server.id}>{server.name} [{server.address}] · {server.osFamily === "windows" ? "RDP" : "SSH"}</option>)}</select></label>}<div className="form-grid"><label>Nhãn hiển thị<input name="label" required minLength={2} maxLength={100} defaultValue={selected?.label ?? ""} placeholder="Ví dụ: Administrator vận hành" /></label><label>Username<input name="username" required maxLength={128} defaultValue={selected?.username ?? ""} autoComplete="off" /></label></div><label>{selected ? "Mật khẩu mới (để trống nếu giữ nguyên)" : "Mật khẩu"}<input name="password" type="password" required={!selected} maxLength={1024} autoComplete="new-password" /></label><fieldset><legend>Người dùng được phép chọn tài khoản này</legend><div className="choice-grid remote-share-grid">{shareableUsers.map((user) => <label key={user.id} aria-label={`Cho phép ${user.displayName || user.username} sử dụng tài khoản này`}><input type="checkbox" name="user_ids" value={user.id} defaultChecked={selected?.userIds.includes(user.id) ?? false} /><span><b>{user.displayName || user.username}</b><small>{user.username} · {user.source === "ldap" ? "AD" : "Local"}</small></span></label>)}</div>{!shareableUsers.length && <div className="empty-state compact">Chưa có người dùng không phải Administrator để share.</div>}</fieldset><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setEditing(null)}>Hủy</button><button className="button primary" disabled={busy}>{busy ? "Đang lưu…" : "Lưu tài khoản"}</button></div></form></ModalShell>}
  </>;
}
