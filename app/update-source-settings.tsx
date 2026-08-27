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
  repositories: Array<{ id: string; currentUrls: string[]; requiredOn: number; optional?: boolean }>;
};

type SavedSourceProfile = {
  profile: string;
  platform: SourcePlatform;
  label: string;
  mode: SourceMode;
  wsusUrl: string;
  repositories: Array<{ id: string; baseUrl: string }>;
  saved: boolean;
  updatedAt: string | null;
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

function ubuntuRepositorySuites(profileKey: string) {
  const codename = profileKey === "ubuntu-22.04" ? "jammy" : "noble";
  const version = profileKey === "ubuntu-22.04" ? "22.04" : "24.04";
  return [
    { id: codename, label: "Base", optional: false, placeholder: `http://pulp.internal/pulp/content/ubuntu/${version}/${codename}/` },
    { id: `${codename}-updates`, label: "Updates", optional: false, placeholder: `http://pulp.internal/pulp/content/ubuntu/${version}/${codename}-updates/` },
    { id: `${codename}-security`, label: "Security", optional: false, placeholder: `http://pulp.internal/pulp/content/ubuntu/${version}/${codename}-security/` },
    { id: `${codename}-backports`, label: "Backports", optional: true, placeholder: `http://pulp.internal/pulp/content/ubuntu/${version}/${codename}-backports/` },
  ];
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
    const definitions: Array<Omit<SourceProfile, "servers">> = [
      { key: "windows-server", label: "Windows Server", platform: "windows", osFamily: "windows" },
      { key: "ubuntu-22.04", label: "Ubuntu 22.04", platform: "ubuntu", osFamily: "linux" },
      { key: "ubuntu-24.04", label: "Ubuntu 24.04", platform: "ubuntu", osFamily: "linux" },
      { key: "oracle-7", label: "Oracle Linux 7", platform: "oracle", osFamily: "linux" },
      { key: "oracle-8", label: "Oracle Linux 8", platform: "oracle", osFamily: "linux" },
    ];
    const grouped = new Map(definitions.map((profile) => [profile.key, { ...profile, servers: [] } as SourceProfile]));
    for (const server of servers) {
      const profile = profileForServer(server);
      if (!profile) continue;
      grouped.get(profile.key)?.servers.push(server);
    }
    return definitions.map((profile) => grouped.get(profile.key) as SourceProfile);
  }, [servers]);
  const unsupportedCount = servers.filter((server) => !profileForServer(server)).length;
  const [profileKey, setProfileKey] = useState("");
  const selectedProfile = profiles.find((profile) => profile.key === profileKey) ?? profiles[0];
  const profileSignature = selectedProfile?.servers.map((server) => server.id).join("|") ?? "";
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [catalog, setCatalog] = useState<SourceCatalog | null>(null);
  const [mode, setMode] = useState<SourceMode>("default");
  const [ubuntuUrls, setUbuntuUrls] = useState<Record<string, string>>({});
  const [wsusUrl, setWsusUrl] = useState("");
  const [oracleUrls, setOracleUrls] = useState<Record<string, string>>({});
  const [reason, setReason] = useState("");
  const [savedProfiles, setSavedProfiles] = useState<Record<string, SavedSourceProfile>>({});
  const [busy, setBusy] = useState<"catalog" | "read" | "save" | "apply" | "">("");
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
      setUbuntuUrls({});
      setWsusUrl("");
      setOracleUrls({});
      setMessage("");
    }, 0);
    return () => window.clearTimeout(timer);
  }, [currentPlatform, currentProfileKey, profileKey, profileSignature]);

  useEffect(() => {
    let active = true;
    async function loadSavedProfiles() {
      try {
        const response = await fetch("/api/v1/settings/update-sources", { headers: { Authorization: `Bearer ${token}` } });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail ?? "Không thể đọc cấu hình mẫu nguồn cập nhật");
        if (!active) return;
        const items = Array.isArray(data.items) ? data.items as SavedSourceProfile[] : [];
        setSavedProfiles(Object.fromEntries(items.map((item) => [item.profile, item])));
      } catch (cause) {
        if (!active) return;
        setMessageError(true);
        setMessage(cause instanceof Error ? cause.message : "Không thể đọc cấu hình mẫu nguồn cập nhật");
      }
    }
    void loadSavedProfiles();
    return () => { active = false; };
  }, [token]);

  useEffect(() => {
    const saved = savedProfiles[currentProfileKey];
    if (!saved?.saved) return;
    const timer = window.setTimeout(() => {
      setMode(saved.mode);
      setWsusUrl(saved.wsusUrl || "");
      const repositories = Object.fromEntries(saved.repositories.map((repository) => [repository.id, repository.baseUrl]));
      setUbuntuUrls(saved.platform === "ubuntu" ? repositories : {});
      setOracleUrls(saved.platform === "oracle" ? repositories : {});
    }, 0);
    return () => window.clearTimeout(timer);
  }, [currentProfileKey, savedProfiles]);

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
        const saved = savedProfiles[nextCatalog.profile];
        const nextMode = saved?.saved
          ? saved.mode
          : ["internet", "wsus", "default", "custom"].includes(nextCatalog.mode)
            ? nextCatalog.mode as SourceMode
            : defaultMode(nextCatalog.platform);
        setMode(nextMode);
        const currentRepositoryUrls = saved?.saved
          ? Object.fromEntries(saved.repositories.map((repository) => [repository.id, repository.baseUrl]))
          : Object.fromEntries(nextCatalog.repositories.map((repository) => [repository.id, repository.currentUrls.length === 1 ? repository.currentUrls[0] : ""]));
        if (!saved?.saved && nextCatalog.platform === "ubuntu" && nextCatalog.repositoryUrl) {
          for (const suite of ubuntuRepositorySuites(nextCatalog.profile)) currentRepositoryUrls[suite.id] ||= nextCatalog.repositoryUrl;
        }
        setUbuntuUrls(nextCatalog.platform === "ubuntu" ? currentRepositoryUrls : {});
        setWsusUrl(saved?.saved ? saved.wsusUrl : nextCatalog.wsusUrl || "");
        setOracleUrls(nextCatalog.platform === "oracle" ? currentRepositoryUrls : {});
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

  function sourceParameters(): Record<string, unknown> {
    if (!selectedProfile) return {};
    if (selectedProfile.platform === "windows") {
      return { mode: mode === "wsus" ? "wsus" : "internet", wsus_url: mode === "wsus" ? wsusUrl.trim() : "" };
    }
    if (selectedProfile.platform === "ubuntu") {
      return mode === "custom"
        ? {
            mode: "custom",
            repositories: ubuntuRepositorySuites(selectedProfile.key)
              .filter((suite) => !suite.optional || Boolean((ubuntuUrls[suite.id] ?? "").trim()))
              .map((suite) => ({ id: suite.id, base_url: (ubuntuUrls[suite.id] ?? "").trim() })),
          }
        : { mode: "default", repositories: [] };
    }
    return mode === "custom"
      ? { mode: "custom", repositories: oracleRepositoryItems.map((repository) => ({ id: repository.id, base_url: (oracleUrls[repository.id] ?? "").trim() })) }
      : { mode: "default", repositories: [] };
  }

  async function persistSourceProfile(parameters: Record<string, unknown>) {
    if (!selectedProfile) throw new Error("Chưa chọn nhóm hệ điều hành");
    const response = await fetch(`/api/v1/settings/update-sources/${encodeURIComponent(selectedProfile.key)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        mode: parameters.mode,
        wsus_url: parameters.wsus_url ?? "",
        repositories: parameters.repositories ?? [],
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail ?? "Không thể lưu cấu hình mẫu nguồn cập nhật");
    const saved = data as SavedSourceProfile;
    setSavedProfiles((current) => ({ ...current, [saved.profile]: saved }));
    return saved;
  }

  async function saveSourceProfile() {
    if (sourceValidationMessage) {
      setMessageError(true);
      setMessage(sourceValidationMessage);
      return;
    }
    setBusy("save");
    setMessage("");
    try {
      await persistSourceProfile(sourceParameters());
      setMessageError(false);
      setMessage(`Đã lưu cấu hình mẫu cho ${selectedProfile?.label}. Khi quay lại nhóm này, các địa chỉ sẽ được điền tự động.`);
      notify(`Đã lưu cấu hình mẫu nguồn cập nhật cho ${selectedProfile?.label}`);
    } catch (cause) {
      setMessageError(true);
      setMessage(cause instanceof Error ? cause.message : "Không thể lưu cấu hình mẫu nguồn cập nhật");
    } finally {
      setBusy("");
    }
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
    if (formValidationMessage) {
      setMessageError(true);
      setMessage(formValidationMessage);
      return;
    }
    if (!selectedProfile) return;
    const parameters = sourceParameters();
    setBusy("apply");
    setMessage("");
    try {
      await createBulkTask("patch.source.configure", parameters, reason.trim());
      setMessageError(false);
      setMessage(`Đã xếp hàng áp dụng cho ${selectedIds.length} máy. Cấu hình mẫu đã lưu không bị thay đổi; Agent sẽ đọc lại nguồn thực tế rồi quét patch đúng OS/version.`);
      notify(`Đã tạo ${selectedIds.length} công việc áp dụng nguồn cập nhật`);
    } catch (cause) {
      setMessageError(true);
      setMessage(cause instanceof Error ? cause.message : "Không thể áp dụng nguồn cập nhật");
    } finally {
      setBusy("");
    }
  }

  const savedProfile = savedProfiles[currentProfileKey];
  const oracleRepositoryItems = catalog?.repositories.length
    ? catalog.repositories
    : savedProfile?.platform === "oracle"
      ? savedProfile.repositories.map((repository) => ({ id: repository.id, currentUrls: [repository.baseUrl], requiredOn: 0 }))
      : [];
  const oracleCustomReady = selectedProfile?.platform !== "oracle" || mode !== "custom" || Boolean(oracleRepositoryItems.length && oracleRepositoryItems.every((repository) => /^https?:\/\/[^\s]+$/i.test((oracleUrls[repository.id] ?? "").trim())));
  const ubuntuCustomReady = selectedProfile?.platform !== "ubuntu" || mode !== "custom" || ubuntuRepositorySuites(selectedProfile.key).every((suite) => {
    const url = (ubuntuUrls[suite.id] ?? "").trim();
    return suite.optional ? !url || /^https?:\/\/[^\s]+$/i.test(url) : /^https?:\/\/[^\s]+$/i.test(url);
  });
  const commonSourceReady = selectedProfile?.platform === "windows"
    ? mode !== "wsus" || /^https?:\/\/[^\s]+$/i.test(wsusUrl.trim())
    : selectedProfile?.platform === "ubuntu"
      ? ubuntuCustomReady
      : oracleCustomReady;
  let sourceValidationMessage = "";
  if (!commonSourceReady) {
    if (selectedProfile?.platform === "ubuntu") sourceValidationMessage = "Nhập URL HTTP/HTTPS hợp lệ cho Base, Updates và Security; Backports có thể để trống.";
    else if (selectedProfile?.platform === "windows") sourceValidationMessage = "Nhập địa chỉ WSUS HTTP/HTTPS hợp lệ.";
    else sourceValidationMessage = "Đọc nguồn từ ít nhất một máy cùng phiên bản, rồi nhập URL HTTP/HTTPS hợp lệ cho toàn bộ repository Oracle đang dùng.";
  }
  const formProblems: string[] = [];
  if (!selectedIds.length) formProblems.push("Chọn ít nhất một máy chủ đích.");
  if (sourceValidationMessage) formProblems.push(sourceValidationMessage);
  if (reason.trim().length < 5) formProblems.push("Nhập lý do hoặc mã ticket tối thiểu 5 ký tự.");
  const formValidationMessage = formProblems.join(" ");

  return <section className="panel update-source-settings-page">
    <div className="update-settings-toolbar">
      <div><h2>Cấu hình nguồn cập nhật</h2><p>Lưu một cấu hình mẫu riêng cho từng OS/version; khi chọn lại nhóm, hệ thống tự điền mirror hoặc WSUS đã lưu.</p></div>
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
      <form className="resource-form update-source-bulk-form" onSubmit={applySources} noValidate>
        <div className="update-settings-section-head"><div><h3>Nguồn áp dụng</h3><p>{selectedProfile?.label}</p></div><div className="update-source-profile-badges"><span className={`state-pill ${savedProfile?.saved ? "healthy" : "warning"}`}>{savedProfile?.saved ? "Đã lưu mẫu" : "Chưa lưu mẫu"}</span><span className="state-pill">{selectedServers.length} máy</span></div></div>
        {selectedProfile?.platform === "windows" ? <fieldset><legend>Chế độ Windows Update</legend><label className="source-choice" aria-label="Microsoft Update qua Internet"><input name="bulk-windows-source" type="radio" checked={mode !== "wsus"} onChange={() => setMode("internet")} /><span><b>Microsoft Update qua Internet</b><small>Gỡ thiết lập WSUS do Agent quản lý và dùng nguồn công khai của Windows.</small></span></label><label className="source-choice" aria-label="Ép dùng WSUS"><input name="bulk-windows-source" type="radio" checked={mode === "wsus"} onChange={() => setMode("wsus")} /><span><b>Ép dùng WSUS</b><small>Đồng bộ WUServer, WUStatusServer và UseWUServer trên toàn bộ máy đã chọn.</small></span></label></fieldset> : selectedProfile?.platform === "ubuntu" ? <fieldset><legend>Repository Ubuntu</legend><label className="source-choice" aria-label="Repo mặc định của Ubuntu"><input name="bulk-ubuntu-source" type="radio" checked={mode !== "custom"} onChange={() => setMode("default")} /><span><b>Repo mặc định của Ubuntu</b><small>Khôi phục nguồn Ubuntu trước lần thay đổi đầu tiên.</small></span></label><label className="source-choice" aria-label="Mirror Ubuntu nội bộ"><input name="bulk-ubuntu-source" type="radio" checked={mode === "custom"} onChange={() => setMode("custom")} /><span><b>Mirror Ubuntu nội bộ</b><small>Chỉ thay nguồn Ubuntu chuẩn; Docker, PPA và repo ứng dụng khác được giữ nguyên.</small></span></label></fieldset> : <fieldset><legend>Repository Oracle Linux</legend><label className="source-choice" aria-label="Repo mặc định của Oracle Linux"><input name="bulk-oracle-source" type="radio" checked={mode !== "custom"} onChange={() => setMode("default")} /><span><b>Repo mặc định của Oracle Linux</b><small>Khôi phục trạng thái các repo hệ điều hành trước lần cấu hình đầu tiên.</small></span></label><label className="source-choice" aria-label="Repo Oracle Linux nội bộ"><input name="bulk-oracle-source" type="radio" checked={mode === "custom"} onChange={() => setMode("custom")} /><span><b>Repo Oracle Linux nội bộ</b><small>Chỉ thay các repo ol7_*/ol8_* thật đang dùng trên từng máy; repo ứng dụng khác được giữ nguyên.</small></span></label></fieldset>}
        {selectedProfile?.platform === "windows" && mode === "wsus" ? <label>Địa chỉ WSUS<input value={wsusUrl} onChange={(event) => setWsusUrl(event.target.value)} placeholder="http://wsus.company.local:8530" spellCheck={false} required /></label> : null}
        {selectedProfile?.platform === "ubuntu" && mode === "custom" ? <fieldset><legend>URL Pulp Distribution cho từng nguồn Ubuntu</legend><div className="update-source-repository-list">{ubuntuRepositorySuites(selectedProfile.key).map((suite) => <label key={suite.id}><span>{suite.label}<small>{suite.id}{suite.optional ? " · tùy chọn" : " · bắt buộc"}</small></span><input value={ubuntuUrls[suite.id] ?? ""} onChange={(event) => setUbuntuUrls((current) => ({ ...current, [suite.id]: event.target.value }))} placeholder={suite.placeholder} spellCheck={false} required={!suite.optional} /></label>)}</div><div className="resource-help">Chữ màu xám trong ô chỉ là ví dụ, không phải dữ liệu đã lưu. Dán đúng URL Distribution mà Pulp hiển thị cho từng suite. Base, Updates và Security là bắt buộc; Backports để trống nếu chưa đồng bộ. Agent tạo từng nguồn APT riêng và giữ nguyên Docker, PPA cùng repository ứng dụng.</div></fieldset> : null}
        {selectedProfile?.platform === "oracle" && mode === "custom" ? <fieldset><legend>URL cho từng repo Oracle đang dùng</legend><div className="update-source-repository-list">{oracleRepositoryItems.map((repository) => <label key={repository.id}><span>{repository.id}<small>{repository.requiredOn}/{selectedIds.length} máy cần repo này</small></span><input value={oracleUrls[repository.id] ?? ""} onChange={(event) => setOracleUrls((current) => ({ ...current, [repository.id]: event.target.value }))} placeholder={`https://repo.company.local/${repository.id}/$basearch`} spellCheck={false} required /></label>)}{!oracleRepositoryItems.length ? <div className="resource-help warning">Cần chọn máy, bấm “Đọc lại nguồn”, đợi công việc hoàn tất rồi “Làm mới dữ liệu” để lấy đúng ID repo từ từng Agent.</div> : null}</div></fieldset> : null}
        <label>Lý do / ticket (chỉ cần khi áp dụng xuống máy)<textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={3} minLength={5} maxLength={2000} required placeholder="CHG-1234 · Mục đích thay đổi nguồn cập nhật" /></label>
        <div className="resource-help">Mỗi máy nhận một công việc riêng và được kiểm tra lại theo OS/version trước khi chạy. Sau khi áp dụng thành công, Agent tự đọc lại nguồn thực tế rồi quét danh sách patch phù hợp.</div>
        {sourceValidationMessage ? <div className="resource-help warning update-source-validation" role="status">{sourceValidationMessage}</div> : null}
        {message ? <div className={`source-message ${messageError ? "failed" : "success"}`}><span>{message}</span>{!messageError && message.includes("xếp hàng") ? <button type="button" onClick={openJobs}>Xem công việc</button> : null}</div> : null}
        <div className="update-source-form-actions">
          <button type="button" className="button ghost" disabled={Boolean(busy)} onClick={() => void saveSourceProfile()}>{busy === "save" ? "Đang lưu…" : "Lưu cấu hình mẫu"}</button>
          <button type="submit" className="button primary update-source-submit" disabled={Boolean(busy)}>{busy === "apply" ? "Đang tạo công việc…" : `Áp dụng (${selectedIds.length} máy)`}</button>
        </div>
      </form>
    </div>
  </section>;
}
