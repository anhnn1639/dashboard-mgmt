"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type OSFamily = "linux" | "windows";

type ManagedServer = {
  id: string;
  name: string;
  address: string;
  osFamily: OSFamily;
  os: string;
  version: string;
  health: string;
};

type SourcePlatform = "windows" | "ubuntu" | "oracle";
type SourceMode = "internet" | "wsus" | "default" | "custom";

type SourceProfile = {
  key: string;
  label: string;
  platform: SourcePlatform;
  osFamily: OSFamily;
  servers: ManagedServer[];
};

type SourceCatalog = {
  ready: boolean;
  profile: string;
  platform: SourcePlatform;
  label: string;
  mode: string;
  repositoryUrl: string;
  wsusUrl: string;
  servers: Array<{ id: string; name: string; address: string; status: string; readAt?: string | null; mode?: string | null }>;
  repositories: Array<{ id: string; currentUrls: string[]; requiredOn: number }>;
};

function profileForServer(server: ManagedServer): Omit<SourceProfile, "servers"> | null {
  if (server.osFamily === "windows") {
    return { key: "windows-server", label: "Windows Server", platform: "windows", osFamily: "windows" };
  }
  const identity = `${server.os} ${server.version}`.toLocaleLowerCase("vi-VN");
  if (identity.includes("ubuntu")) {
    if (identity.includes("22.04")) return { key: "ubuntu-22.04", label: "Ubuntu 22.04", platform: "ubuntu", osFamily: "linux" };
    if (identity.includes("24.04")) return { key: "ubuntu-24.04", label: "Ubuntu 24.04", platform: "ubuntu", osFamily: "linux" };
  }
  if (identity.includes("oracle linux")) {
    const major = /(?:^|\D)(7|8)(?:\.|\D|$)/.exec(identity)?.[1];
    if (major) return { key: `oracle-${major}`, label: `Oracle Linux ${major}`, platform: "oracle", osFamily: "linux" };
  }
  return null;
}

function normalizeSearch(value: string) {
  return value.normalize("NFD").replace(/\p{M}/gu, "").replace(/[đĐ]/g, "d").toLocaleLowerCase("vi-VN").trim();
}

function defaultMode(platform: SourcePlatform): SourceMode {
  return platform === "windows" ? "internet" : "default";
}

export function UpdateSourceSettingsView({
  servers,
  token,
  notify,
  openJobs,
}: {
  servers: ManagedServer[];
  token: string;
  notify: (message: string) => void;
  openJobs: () => void;
}) {
  const profiles = useMemo(() => {
    const grouped = new Map<string, SourceProfile>();
    for (const server of servers) {
      const profile = profileForServer(server);
      if (!profile) continue;
      const current = grouped.get(profile.key) ?? { ...profile, servers: [] };
      current.servers.push(server);
      grouped.set(profile.key, current);
    }
    const order = ["windows-server", "ubuntu-22.04", "ubuntu-24.04", "oracle-7", "oracle-8"];
    return [...grouped.values()].sort((left, right) => order.indexOf(left.key) - order.indexOf(right.key));
  }, [servers]);
  const unsupportedCount = servers.filter((server) => !profileForServer(server)).length;
  const [profileKey, setProfileKey] = useState("");
  const selectedProfile = profiles.find((profile) => profile.key === profileKey) ?? profiles[0];
  const profileSignature = selectedProfile?.servers.map((server) => server.id).join("|") ?? "";
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [catalog, setCatalog] = useState<SourceCatalog | null>(null);
  const [mode, setMode] = useState<SourceMode>("default");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [wsusUrl, setWsusUrl] = useState("");
  const [oracleUrls, setOracleUrls] = useState<Record<string, string>>({});
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"catalog" | "read" | "apply" | "">("");
  const [message, setMessage] = useState("");
  const [messageError, setMessageError] = useState(false);

  const currentProfileKey = selectedProfile?.key ?? "";
  const currentPlatform = selectedProfile?.platform;
  useEffect(() => {
    if (!currentProfileKey || !currentPlatform) return;
    const timer = window.setTimeout(() => {
      if (profileKey !== currentProfileKey) setProfileKey(currentProfileKey);
      setSelectedIds(profileSignature ? profileSignature.split("|") : []);
      setSearch("");
      setCatalog(null);
      setMode(defaultMode(currentPlatform));
      setRepositoryUrl("");
      setWsusUrl("");
      setOracleUrls({});
      setMessage("");
    }, 0);
    return () => window.clearTimeout(timer);
  }, [currentPlatform, currentProfileKey, profileKey, profileSignature]);

  const selectedServers = selectedProfile?.servers.filter((server) => selectedIds.includes(server.id)) ?? [];
  const visibleServers = selectedProfile?.servers.filter((server) => {
    const needle = normalizeSearch(search);
    return !needle || normalizeSearch(`${server.name} ${server.address} ${server.os} ${server.version}`).includes(needle);
  }) ?? [];

  function toggleServer(serverId: string) {
    setSelectedIds((current) => current.includes(serverId) ? current.filter((id) => id !== serverId) : [...current, serverId]);
    setCatalog(null);
    setMessage("");
  }

  function toggleVisible() {
    const visibleIds = visibleServers.map((server) => server.id);
    const allSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedIds.includes(id));
    setSelectedIds((current) => allSelected ? current.filter((id) => !visibleIds.includes(id)) : Array.from(new Set([...current, ...visibleIds])));
    setCatalog(null);
    setMessage("");
  }

  async function loadCatalog(hydrate = true) {
    if (!selectedProfile || !selectedIds.length) return;
    setBusy("catalog");
    setMessage("");
    try {
      const response = await fetch("/api/v1/bulk-update-sources/catalog", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ os_family: selectedProfile.osFamily, server_ids: selectedIds }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail ?? "Không thể đọc cấu hình nguồn cập nhật");
      const nextCatalog = data as SourceCatalog;
      setCatalog(nextCatalog);
      if (hydrate) {
        const nextMode = ["internet", "wsus", "default", "custom"].includes(nextCatalog.mode)
          ? nextCatalog.mode as SourceMode
          : defaultMode(nextCatalog.platform);
        setMode(nextMode);
        setRepositoryUrl(nextCatalog.repositoryUrl || "");
        setWsusUrl(nextCatalog.wsusUrl || "");
        setOracleUrls(Object.fromEntries(nextCatalog.repositories.map((repository) => [repository.id, repository.currentUrls.length === 1 ? repository.currentUrls[0] : ""])));
      }
    } catch (cause) {
      setCatalog(null);
      setMessageError(true);
      setMessage(cause instanceof Error ? cause.message : "Không thể đọc cấu hình nguồn cập nhật");
    } finally {
      setBusy("");
    }
  }

  async function createBulkTask(action: "patch.source.read" | "patch.source.configure", parameters: Record<string, unknown>, taskReason: string) {
    if (!selectedProfile || !selectedIds.length) return false;
    const response = await fetch("/api/v1/bulk-tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ os_family: selectedProfile.osFamily, server_ids: selectedIds, action, parameters, reason: taskReason }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail ?? "Không thể tạo công việc hàng loạt");
    return true;
  }

  async function readSources() {
    setBusy("read");
    setMessage("");
    try {
      await createBulkTask("patch.source.read", {}, `Đọc nguồn cập nhật trên ${selectedIds.length} máy cùng hệ điều hành`);
      setMessageError(false);
      setMessage(`Đã xếp hàng ${selectedIds.length} công việc đọc nguồn. Mở Công việc để theo dõi, sau đó làm mới dữ liệu tại đây.`);
      notify(`Đã xếp hàng đọc nguồn cập nhật cho ${selectedIds.length} máy`);
    } catch (cause) {
      setMessageError(true);
      setMessage(cause instanceof Error ? cause.message : "Không thể đọc nguồn cập nhật");
    } finally {
      setBusy("");
    }
  }

  async function applySources(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedProfile) return;
    let parameters: Record<string, unknown>;
    if (selectedProfile.platform === "windows") {
      parameters = { mode: mode === "wsus" ? "wsus" : "internet", wsus_url: mode === "wsus" ? wsusUrl.trim() : "" };
    } else if (selectedProfile.platform === "ubuntu") {
      parameters = { mode: mode === "custom" ? "custom" : "default", repository_url: mode === "custom" ? repositoryUrl.trim() : "" };
    } else {
      parameters = mode === "custom"
        ? { mode: "custom", repositories: (catalog?.repositories ?? []).map((repository) => ({ id: repository.id, base_url: (oracleUrls[repository.id] ?? "").trim() })) }
        : { mode: "default", repositories: [] };
    }
    setBusy("apply");
    setMessage("");
    try {
      await createBulkTask("patch.source.configure", parameters, reason.trim());
      setMessageError(false);
      setMessage(`Đã xếp hàng áp dụng cho ${selectedIds.length} máy. Mỗi Agent sẽ tự đọc lại nguồn và quét patch đúng OS/version sau khi cấu hình xong.`);
      notify(`Đã tạo ${selectedIds.length} công việc cấu hình nguồn cập nhật`);
    } catch (cause) {
      setMessageError(true);
      setMessage(cause instanceof Error ? cause.message : "Không thể áp dụng nguồn cập nhật");
    } finally {
      setBusy("");
    }
  }

  const oracleCustomReady = selectedProfile?.platform !== "oracle" || mode !== "custom" || Boolean(catalog?.ready && catalog.repositories.length && catalog.repositories.every((repository) => /^https?:\/\/[^\s]+$/i.test((oracleUrls[repository.id] ?? "").trim())));
  const commonSourceReady = selectedProfile?.platform === "windows"
    ? mode !== "wsus" || /^https?:\/\/[^\s]+$/i.test(wsusUrl.trim())
    : selectedProfile?.platform === "ubuntu"
      ? mode !== "custom" || /^https?:\/\/[^\s]+$/i.test(repositoryUrl.trim())
      : oracleCustomReady;

  if (!profiles.length) {
    return <section className="panel update-source-settings-page"><div className="empty-state">Chưa có máy chủ Windows Server, Ubuntu 22.04/24.04 hoặc Oracle Linux 7/8 để cấu hình.</div></section>;
  }

  return <section className="panel update-source-settings-page">
    <div className="update-settings-toolbar">
      <div><h2>Cấu hình nguồn cập nhật hàng loạt</h2><p>Chọn đúng nhóm hệ điều hành, kiểm tra máy đích rồi áp dụng một lần cho toàn bộ nhóm.</p></div>
      <div className="update-settings-toolbar-actions"><button type="button" className="button ghost" disabled={Boolean(busy) || !selectedIds.length} onClick={() => void loadCatalog(true)}>{busy === "catalog" ? "Đang đọc…" : "↻ Làm mới dữ liệu"}</button><button type="button" className="button ghost" disabled={Boolean(busy) || !selectedIds.length} onClick={() => void readSources()}>{busy === "read" ? "Đang tạo…" : `Đọc lại nguồn (${selectedIds.length})`}</button></div>
    </div>
    <div className="update-settings-filter-grid">
      <label>Nhóm hệ điều hành<select value={selectedProfile?.key ?? ""} onChange={(event) => setProfileKey(event.target.value)}>{profiles.map((profile) => <option key={profile.key} value={profile.key}>{profile.label} · {profile.servers.length} máy</option>)}</select></label>
      <label>Tìm máy chủ<input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Hostname, IP hoặc phiên bản…" /></label>
    </div>
    {unsupportedCount > 0 ? <div className="resource-help">{unsupportedCount} máy dùng hệ điều hành ngoài phạm vi cấu hình nguồn hiện tại nên không xuất hiện trong danh sách.</div> : null}
    <div className="update-settings-layout">
      <section className="update-settings-targets">
        <div className="update-settings-section-head"><div><h3>Máy chủ đích</h3><p>{selectedIds.length}/{selectedProfile?.servers.length ?? 0} máy đã chọn</p></div><button type="button" onClick={toggleVisible}>{visibleServers.length > 0 && visibleServers.every((server) => selectedIds.includes(server.id)) ? "Bỏ chọn kết quả" : "Chọn kết quả"}</button></div>
        <div className="update-source-server-list">{visibleServers.map((server) => <label key={server.id}><input type="checkbox" checked={selectedIds.includes(server.id)} onChange={() => toggleServer(server.id)} /><span><b>{server.name}</b><small>{server.address} · {server.os} {server.version}</small></span><em className={server.health}>{server.health === "offline" ? "Chờ kết nối" : "Sẵn sàng"}</em></label>)}{!visibleServers.length ? <div className="empty-state">Không có máy phù hợp bộ lọc.</div> : null}</div>
        {catalog ? <div className="update-source-read-state"><b>Nguồn hiện tại</b><span>{catalog.servers.filter((server) => server.status === "complete").length}/{catalog.servers.length} máy đã đọc thành công</span>{catalog.mode === "mixed" ? <small>Các máy đang dùng nguồn khác nhau; lựa chọn bên phải sẽ đồng bộ lại toàn bộ máy đã chọn.</small> : null}</div> : <div className="update-source-read-state muted"><span>Nhấn “Làm mới dữ liệu” để đối chiếu nguồn hiện tại của các máy đã chọn.</span></div>}
      </section>
      <form className="resource-form update-source-bulk-form" onSubmit={applySources}>
        <div className="update-settings-section-head"><div><h3>Nguồn áp dụng</h3><p>{selectedProfile?.label}</p></div><span className="state-pill">{selectedServers.length} máy</span></div>
        {selectedProfile?.platform === "windows" ? <fieldset><legend>Chế độ Windows Update</legend><label className="source-choice" aria-label="Microsoft Update qua Internet"><input name="bulk-windows-source" type="radio" checked={mode !== "wsus"} onChange={() => setMode("internet")} /><span><b>Microsoft Update qua Internet</b><small>Gỡ thiết lập WSUS do Agent quản lý và dùng nguồn công khai của Windows.</small></span></label><label className="source-choice" aria-label="Ép dùng WSUS"><input name="bulk-windows-source" type="radio" checked={mode === "wsus"} onChange={() => setMode("wsus")} /><span><b>Ép dùng WSUS</b><small>Đồng bộ WUServer, WUStatusServer và UseWUServer trên toàn bộ máy đã chọn.</small></span></label></fieldset> : selectedProfile?.platform === "ubuntu" ? <fieldset><legend>Repository Ubuntu</legend><label className="source-choice" aria-label="Repo mặc định của Ubuntu"><input name="bulk-ubuntu-source" type="radio" checked={mode !== "custom"} onChange={() => setMode("default")} /><span><b>Repo mặc định của Ubuntu</b><small>Khôi phục nguồn Ubuntu trước lần thay đổi đầu tiên.</small></span></label><label className="source-choice" aria-label="Mirror Ubuntu nội bộ"><input name="bulk-ubuntu-source" type="radio" checked={mode === "custom"} onChange={() => setMode("custom")} /><span><b>Mirror Ubuntu nội bộ</b><small>Chỉ thay nguồn Ubuntu chuẩn; Docker, PPA và repo ứng dụng khác được giữ nguyên.</small></span></label></fieldset> : <fieldset><legend>Repository Oracle Linux</legend><label className="source-choice" aria-label="Repo mặc định của Oracle Linux"><input name="bulk-oracle-source" type="radio" checked={mode !== "custom"} onChange={() => setMode("default")} /><span><b>Repo mặc định của Oracle Linux</b><small>Khôi phục trạng thái các repo hệ điều hành trước lần cấu hình đầu tiên.</small></span></label><label className="source-choice" aria-label="Repo Oracle Linux nội bộ"><input name="bulk-oracle-source" type="radio" checked={mode === "custom"} onChange={() => setMode("custom")} /><span><b>Repo Oracle Linux nội bộ</b><small>Chỉ thay các repo ol7_*/ol8_* thật đang dùng trên từng máy; repo ứng dụng khác được giữ nguyên.</small></span></label></fieldset>}
        {selectedProfile?.platform === "windows" && mode === "wsus" ? <label>Địa chỉ WSUS<input value={wsusUrl} onChange={(event) => setWsusUrl(event.target.value)} placeholder="http://wsus.company.local:8530" spellCheck={false} required /></label> : null}
        {selectedProfile?.platform === "ubuntu" && mode === "custom" ? <label>URL gốc của mirror Ubuntu<input value={repositoryUrl} onChange={(event) => setRepositoryUrl(event.target.value)} placeholder="https://repo.company.local/ubuntu" spellCheck={false} required /><small>Mirror phải có đủ suite tương ứng với {selectedProfile.label}, updates, backports và security.</small></label> : null}
        {selectedProfile?.platform === "oracle" && mode === "custom" ? <fieldset><legend>URL cho từng repo Oracle đang dùng</legend><div className="update-source-repository-list">{catalog?.repositories.map((repository) => <label key={repository.id}><span>{repository.id}<small>{repository.requiredOn}/{selectedIds.length} máy cần repo này</small></span><input value={oracleUrls[repository.id] ?? ""} onChange={(event) => setOracleUrls((current) => ({ ...current, [repository.id]: event.target.value }))} placeholder={`https://repo.company.local/${repository.id}/$basearch`} spellCheck={false} required /></label>)}{!catalog?.ready || !catalog.repositories.length ? <div className="resource-help warning">Cần chọn máy, bấm “Đọc lại nguồn”, đợi công việc hoàn tất rồi “Làm mới dữ liệu” để lấy đúng ID repo từ từng Agent.</div> : null}</div></fieldset> : null}
        <label>Lý do / ticket<textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={3} minLength={5} maxLength={2000} required placeholder="CHG-1234 · Mục đích thay đổi nguồn cập nhật" /></label>
        <div className="resource-help">Mỗi máy nhận một công việc riêng và được kiểm tra lại theo OS/version trước khi chạy. Sau khi áp dụng thành công, Agent tự đọc lại nguồn thực tế rồi quét danh sách patch phù hợp.</div>
        {message ? <div className={`source-message ${messageError ? "failed" : "success"}`}><span>{message}</span>{!messageError ? <button type="button" onClick={openJobs}>Xem công việc</button> : null}</div> : null}
        <button type="submit" className="button primary update-source-submit" disabled={Boolean(busy) || !selectedIds.length || reason.trim().length < 5 || !commonSourceReady}>{busy === "apply" ? "Đang tạo công việc…" : `Áp dụng cho ${selectedIds.length} máy`}</button>
      </form>
    </div>
  </section>;
}
