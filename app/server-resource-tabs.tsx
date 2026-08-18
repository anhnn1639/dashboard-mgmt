"use client";

import { CSSProperties, FormEvent, Fragment, ReactNode, useEffect, useMemo, useState } from "react";

export type QueueOperation = (
  action: string,
  parameters: Record<string, unknown>,
  reason: string,
) => Promise<boolean>;

export type OperationJob = {
  id: string;
  action: string;
  status: string;
  reason: string;
  output?: string;
  exitCode?: number | null;
  createdAt: string;
};

export function parseObject(output: string | undefined): Record<string, unknown> {
  if (!output) return {};
  try {
    const parsed = JSON.parse(output) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

export function parseRows<T>(output: string | undefined): T[] {
  if (!output) return [];
  try {
    const parsed = JSON.parse(output) as unknown;
    return (Array.isArray(parsed) ? parsed : parsed ? [parsed] : []) as T[];
  } catch {
    return [];
  }
}

function bytes(value: unknown) {
  const number = Number(value ?? 0);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function formatBytes(value: unknown) {
  const amount = bytes(value);
  if (!amount) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(amount) / Math.log(1024)));
  return `${(amount / 1024 ** index).toFixed(index > 2 ? 1 : 0)} ${units[index]}`;
}

export function ModalShell({
  title,
  subtitle,
  close,
  children,
  className = "",
  footer,
}: {
  title: string;
  subtitle: string;
  close: () => void;
  children: ReactNode;
  className?: string;
  footer?: ReactNode;
}) {
  return (
    <div className="modal-backdrop resource-modal-backdrop">
      <button className="modal-dismiss" type="button" aria-label="Đóng" onClick={close} />
      <section className={`modal resource-modal ${className}`.trim()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <div>
            <span className="modal-icon">◇</span>
            <div><h2>{title}</h2><p>{subtitle}</p></div>
          </div>
          <button type="button" aria-label="Đóng" onClick={close}>×</button>
        </div>
        <div className="resource-modal-body">{children}</div>
        {footer ? <div className="resource-modal-footer">{footer}</div> : null}
      </section>
    </div>
  );
}

function PendingState({ job }: { job?: OperationJob }) {
  if (!job || !["queued", "dispatched", "failed"].includes(job.status)) return null;
  return (
    <div className={`resource-job-state ${job.status}`}>
      <b>{job.status === "queued" ? "Đang chờ Agent" : job.status === "dispatched" ? "Agent đang xử lý" : "Tác vụ thất bại"}</b>
      <span>{job.reason}</span>
      {job.status === "failed" && <pre>{job.output || "Agent không trả về nội dung lỗi."}</pre>}
    </div>
  );
}

type StorageNode = {
  id?: string;
  name?: string;
  path?: string;
  type?: string;
  filesystem?: string;
  label?: string;
  sizeBytes?: number;
  freeBytes?: number;
  extendableBytes?: number;
  shrinkableBytes?: number;
  unallocatedBytes?: number;
  largestFreeExtentBytes?: number;
  offsetBytes?: number;
  endOffsetBytes?: number;
  mountpoints?: string[];
  children?: StorageNode[];
  partitions?: StorageNode[];
  partitionNumber?: number;
  diskNumber?: number;
  driveLetter?: string;
  number?: number;
  model?: string;
  serial?: string;
  vgName?: string;
  partitionTable?: string;
  protected?: boolean;
  resizeProtected?: boolean;
  resizeReason?: string;
  readOnly?: boolean;
  freeRegions?: Array<{ startBytes: number; endBytes: number; sizeBytes: number }>;
};

type LogicalVolume = StorageNode & {
  vgName?: string;
};

type VolumeGroup = {
  name: string;
  sizeBytes: number;
  freeBytes: number;
  physicalVolumes: string[];
  logicalVolumes: string[];
};

type StorageScan = {
  platform: "windows" | "linux" | "";
  disks: StorageNode[];
  volumeGroups: VolumeGroup[];
  logicalVolumes: LogicalVolume[];
  lvmCandidates: Array<{ path: string; sizeBytes: number }>;
  capabilities: { partitionCreate?: boolean; lvm?: boolean };
};

function objectArray(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item));
  return value && typeof value === "object" ? [value as Record<string, unknown>] : [];
}

function stringArray(value: unknown): string[] {
  const scalar = (item: unknown) =>
    typeof item === "string" || typeof item === "number" || typeof item === "boolean"
      ? String(item)
      : "";
  if (Array.isArray(value)) return value.map(scalar).filter(Boolean);
  const item = scalar(value);
  return item ? [item] : [];
}

function storageText(value: unknown): string | undefined {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean"
    ? String(value)
    : undefined;
}

function normalizeStorageNode(value: Record<string, unknown>): StorageNode {
  return {
    id: storageText(value.id),
    name: storageText(value.name),
    path: storageText(value.path),
    type: storageText(value.type),
    filesystem: storageText(value.filesystem),
    label: storageText(value.label),
    driveLetter: storageText(value.driveLetter),
    model: storageText(value.model),
    serial: storageText(value.serial),
    vgName: storageText(value.vgName),
    partitionTable: storageText(value.partitionTable),
    sizeBytes: bytes(value.sizeBytes),
    freeBytes: bytes(value.freeBytes),
    extendableBytes: bytes(value.extendableBytes),
    shrinkableBytes: bytes(value.shrinkableBytes),
    unallocatedBytes: bytes(value.unallocatedBytes),
    largestFreeExtentBytes: bytes(value.largestFreeExtentBytes),
    offsetBytes: bytes(value.offsetBytes),
    endOffsetBytes: bytes(value.endOffsetBytes),
    partitionNumber: Number(value.partitionNumber) || undefined,
    diskNumber: Number(value.diskNumber) || undefined,
    number: Number(value.number) || 0,
    protected: value.protected === true,
    resizeProtected: value.resizeProtected === true,
    resizeReason: storageText(value.resizeReason),
    readOnly: value.readOnly === true,
    mountpoints: stringArray(value.mountpoints),
    children: objectArray(value.children).map(normalizeStorageNode),
    partitions: objectArray(value.partitions).map(normalizeStorageNode),
    freeRegions: objectArray(value.freeRegions).map((region) => ({
      startBytes: bytes(region.startBytes),
      endBytes: bytes(region.endBytes),
      sizeBytes: bytes(region.sizeBytes),
    })),
  } as StorageNode;
}

function parseStorage(output: string | undefined): StorageScan {
  const raw = parseObject(output);
  return {
    platform: raw.platform === "windows" || raw.platform === "linux" ? raw.platform : "",
    disks: objectArray(raw.disks).map(normalizeStorageNode),
    volumeGroups: objectArray(raw.volumeGroups).map((group) => ({
      ...group,
      physicalVolumes: stringArray(group.physicalVolumes),
      logicalVolumes: stringArray(group.logicalVolumes),
    })) as VolumeGroup[],
    logicalVolumes: objectArray(raw.logicalVolumes).map(normalizeStorageNode) as LogicalVolume[],
    lvmCandidates: objectArray(raw.lvmCandidates).map((item) => ({ path: String(item.path ?? ""), sizeBytes: bytes(item.sizeBytes) })).filter((item) => item.path),
    capabilities: raw.capabilities && typeof raw.capabilities === "object" ? raw.capabilities as StorageScan["capabilities"] : {},
  };
}

function logicalVolumeMapperPath(logical: LogicalVolume) {
  if (!logical.vgName || !logical.name) return "";
  const escapeMapperName = (value: string) => value.replaceAll("-", "--");
  return `/dev/mapper/${escapeMapperName(logical.vgName)}-${escapeMapperName(logical.name)}`;
}

type StorageTarget = {
  key: string;
  kind: "windows_partition" | "linux_partition" | "linux_lv" | "linux_vg";
  label: string;
  path?: string;
  diskNumber?: number;
  partitionNumber?: number;
  extendableBytes?: number;
  shrinkableBytes?: number;
  filesystem?: string;
  protected?: boolean;
  resizeProtected?: boolean;
  resizeReason?: string;
  mounted?: boolean;
  name?: string;
};

export function StorageResourceTab({
  output,
  job,
  serverName,
  osFamily,
  busy,
  refresh,
  queue,
}: {
  output?: string;
  job?: OperationJob;
  serverName: string;
  osFamily: "windows" | "linux";
  busy: boolean;
  refresh: () => void;
  queue: QueueOperation;
}) {
  const scan = useMemo(() => parseStorage(output), [output]);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [selected, setSelected] = useState<StorageTarget | null>(null);
  const [modal, setModal] = useState<"create" | "extend" | "shrink" | "delete" | null>(null);
  const [createKind, setCreateKind] = useState(osFamily === "windows" ? "windows_partition" : "linux_partition");
  const [createTarget, setCreateTarget] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const disks = scan.disks;
  const windowsLayoutWarnings = osFamily === "windows" ? disks.flatMap((disk) => {
    const segments = disk.partitions ?? [];
    return segments.flatMap((partition, index) => {
      if (!partition.partitionNumber || !partition.driveLetter || bytes(partition.extendableBytes) > 0) return [];
      const freeIndex = segments.findIndex((segment, candidateIndex) => candidateIndex > index && segment.type === "unallocated" && bytes(segment.sizeBytes) >= 1024 ** 2);
      if (freeIndex < 0 || freeIndex === index + 1) return [];
      const blockers = segments.slice(index + 1, freeIndex).filter((segment) => segment.type !== "unallocated");
      if (!blockers.length) return [];
      return [{
        key: `${disk.number}:${partition.partitionNumber}:${freeIndex}`,
        volume: partition.driveLetter ? `${partition.driveLetter}:` : `Partition ${partition.partitionNumber}`,
        disk: disk.number,
        freeBytes: bytes(segments[freeIndex].sizeBytes),
        blockers: blockers.map((segment) => segment.driveLetter ? `${segment.driveLetter}:` : segment.type || `Partition ${segment.partitionNumber}`).join(", "),
      }];
    });
  }) : [];

  function toggle(key: string) {
    setExpanded((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key]);
  }

  function nodeTarget(node: StorageNode, disk: StorageNode): StorageTarget | null {
    if (osFamily === "windows") {
      if (!node.partitionNumber) return null;
      return {
        key: `windows:${disk.number}:${node.partitionNumber}`,
        kind: "windows_partition",
        label: `${node.driveLetter ? `${node.driveLetter}:` : `Partition ${node.partitionNumber}`} trên Disk ${disk.number}`,
        diskNumber: Number(disk.number),
        partitionNumber: Number(node.partitionNumber),
        extendableBytes: bytes(node.extendableBytes),
        shrinkableBytes: bytes(node.shrinkableBytes),
        filesystem: node.filesystem,
        protected: Boolean(node.protected),
        resizeProtected: Boolean(node.resizeProtected),
        resizeReason: node.resizeReason,
        mounted: false,
      };
    }
    if (node.type === "part") {
      return {
        key: `partition:${node.path}`,
        kind: "linux_partition",
        label: String(node.path),
        path: node.path,
        partitionNumber: Number(node.partitionNumber),
        extendableBytes: bytes(node.extendableBytes),
        protected: Boolean(node.protected),
        mounted: Boolean(node.mountpoints?.length),
      };
    }
    if (node.type === "lvm") {
      const logical = scan.logicalVolumes.find((item) => item.path === node.path || logicalVolumeMapperPath(item) === node.path);
      return logical ? {
        key: `lv:${logical.path}`,
        kind: "linux_lv",
        label: String(logical.path),
        path: logical.path,
        extendableBytes: bytes(logical.extendableBytes),
        protected: Boolean(logical.protected),
        mounted: Boolean(logical.mountpoints?.length),
      } : null;
    }
    return null;
  }

  function renderNode(node: StorageNode, disk: StorageNode, depth: number) {
    const children = node.children ?? [];
    const key = String(node.id ?? node.path ?? `${node.name}-${depth}`);
    const target = nodeTarget(node, disk);
    const isSelected = Boolean(target && selected?.key === target.key);
    const extendCapacity = bytes(target?.extendableBytes);
    const shrinkCapacity = bytes(target?.shrinkableBytes);
    const protectedPartition = Boolean(target?.protected && target.kind === "linux_partition");
    const resizeProtected = Boolean(target?.resizeProtected || protectedPartition);
    const canExtend = Boolean(target && extendCapacity >= 1024 ** 2 && !resizeProtected);
    const canShrink = Boolean(target?.kind === "windows_partition" && target.filesystem?.toUpperCase() === "NTFS" && shrinkCapacity >= 16 * 1024 ** 2 && !resizeProtected);
    const extendReason = !target
      ? ""
      : resizeProtected
        ? target.resizeReason || "Partition hệ thống này được bảo vệ và không thể resize từ dashboard."
        : extendCapacity < 1024 ** 2
          ? target.kind === "linux_lv"
            ? "Volume Group không còn dung lượng trống để extend Logical Volume."
            : target.kind === "windows_partition" && bytes(disk.unallocatedBytes) >= 1024 ** 2
              ? `Disk còn ${formatBytes(disk.unallocatedBytes)} unallocated nhưng không nằm liền kề partition này; partition Recovery hoặc partition khác đang nằm ở giữa.`
              : "Không có unallocated space liền kề partition. Hãy tăng virtual disk và quét lại."
          : `Có thể mở rộng tối đa ${formatBytes(extendCapacity)}.`;
    const shrinkReason = !target
      ? ""
      : resizeProtected
        ? target.resizeReason || "Partition hệ thống này được bảo vệ."
        : target.filesystem?.toUpperCase() !== "NTFS"
          ? "Windows chỉ hỗ trợ Shrink an toàn cho volume NTFS."
          : shrinkCapacity < 16 * 1024 ** 2
            ? "Windows không xác nhận đủ dung lượng có thể Shrink; file không thể di chuyển có thể đang nằm cuối volume."
            : `Có thể Shrink tối đa ${formatBytes(shrinkCapacity)} theo trạng thái vừa quét.`;
    const unallocated = node.type === "unallocated";
    const displayName = unallocated
      ? "Unallocated"
      : node.driveLetter
        ? `${node.driveLetter}:`
        : osFamily === "windows" && node.partitionNumber
          ? `${node.type || "Partition"} · Partition ${node.partitionNumber}`
          : node.path ?? node.name ?? "Thiết bị";
    const physicalPosition = osFamily === "windows"
      ? `${node.partitionNumber ? `#${node.partitionNumber} · ` : ""}${formatBytes(node.offsetBytes)} → ${formatBytes(node.endOffsetBytes)}`
      : node.mountpoints?.join(", ") || "—";
    return (
      <div key={key} className={`storage-tree-item ${unallocated ? "unallocated" : ""}`}>
        <div className={`storage-tree-row ${isSelected ? "selected" : ""}`} style={{ "--tree-depth": depth } as CSSProperties}>
          <span className="storage-tree-toggle">
            {children.length ? <button type="button" onClick={() => toggle(key)} aria-label="Mở cây phân vùng">{expanded.includes(key) ? "⌄" : "›"}</button> : <i />}
            {target && <input type="checkbox" checked={isSelected} onChange={() => setSelected(isSelected ? null : target)} disabled={target.protected} aria-label={`Chọn ${target.label}`} />}
          </span>
          <span className="storage-name"><b>{displayName}</b><small>{unallocated ? "Vùng trống chưa thuộc volume nào" : node.label || node.type || "partition"}{node.protected && !unallocated ? " · được bảo vệ" : ""}</small></span>
          <span>{node.filesystem || "—"}</span>
          <span>{formatBytes(node.sizeBytes)}</span>
          <span>{physicalPosition}</span>
          <span>{unallocated ? formatBytes(node.sizeBytes) : formatBytes(node.freeBytes)}</span>
          <span className="storage-row-actions">
            {target && <button type="button" disabled={!canExtend} title={extendReason} onClick={() => { setSelected(target); setModal("extend"); }}>Extend</button>}
            {target?.kind === "windows_partition" && <button type="button" disabled={!canShrink} title={shrinkReason} onClick={() => { setSelected(target); setModal("shrink"); }}>Shrink</button>}
          </span>
        </div>
        {children.length > 0 && expanded.includes(key) && <div>{children.map((child) => renderNode(child, disk, depth + 1))}</div>}
      </div>
    );
  }

  async function submitExtend(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const form = new FormData(event.currentTarget);
    const addBytes = Math.floor(Number(form.get("size_gb")) * 1024 ** 3);
    const parameters: Record<string, unknown> = { kind: selected.kind, add_bytes: addBytes };
    if (selected.path) parameters.path = selected.path;
    if (selected.diskNumber !== undefined) parameters.disk_number = selected.diskNumber;
    if (selected.partitionNumber !== undefined) parameters.partition_number = selected.partitionNumber;
    if (!await queue("storage.extend", parameters, `Extend ${selected.label} trên ${serverName}`)) return;
    setModal(null);
  }

  async function submitShrink(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || selected.kind !== "windows_partition") return;
    const form = new FormData(event.currentTarget);
    const shrinkBytes = Math.floor(Number(form.get("size_gb")) * 1024 ** 3);
    const parameters: Record<string, unknown> = {
      kind: selected.kind,
      disk_number: selected.diskNumber,
      partition_number: selected.partitionNumber,
      shrink_bytes: shrinkBytes,
    };
    if (!await queue("storage.shrink", parameters, `Shrink ${selected.label} trên ${serverName}`)) return;
    setModal(null);
  }

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const sizeBytes = Math.floor(Number(form.get("size_gb")) * 1024 ** 3);
    const parameters: Record<string, unknown> = { kind: createKind, size_bytes: sizeBytes };
    if (createKind === "windows_partition") {
      parameters.disk_number = Number(form.get("disk_number"));
      parameters.filesystem = form.get("filesystem");
      parameters.label = form.get("label");
      if (form.get("drive_letter")) parameters.drive_letter = form.get("drive_letter");
    } else if (createKind === "linux_partition") {
      const [disk, start] = String(form.get("region")).split("|");
      parameters.disk = disk;
      parameters.start_bytes = Number(start);
      parameters.filesystem = form.get("filesystem");
      parameters.label = form.get("label");
      parameters.mount_point = form.get("mount_point");
    } else if (createKind === "linux_lv") {
      parameters.vg_name = form.get("vg_name");
      parameters.name = form.get("name");
      parameters.filesystem = form.get("filesystem");
      parameters.label = form.get("label");
      parameters.mount_point = form.get("mount_point");
    } else {
      const candidate = scan.lvmCandidates.find((item) => item.path === form.get("device"));
      parameters.device = form.get("device");
      parameters.name = form.get("name");
      parameters.size_bytes = candidate?.sizeBytes ?? sizeBytes;
    }
    if (!await queue("storage.create", parameters, `Tạo ${createKind} trên ${serverName}`)) return;
    setModal(null);
  }

  async function submitDelete() {
    if (!selected || confirmation !== "DELETE") return;
    const parameters: Record<string, unknown> = { kind: selected.kind };
    if (selected.path) parameters.path = selected.path;
    if (selected.name) parameters.name = selected.name;
    if (selected.diskNumber !== undefined) parameters.disk_number = selected.diskNumber;
    if (selected.partitionNumber !== undefined) parameters.partition_number = selected.partitionNumber;
    if (!await queue("storage.delete", parameters, `Xóa ${selected.label} trên ${serverName}`)) return;
    setSelected(null);
    setModal(null);
    setConfirmation("");
  }

  const freeRegions = disks.flatMap((disk) => (disk.freeRegions ?? []).map((region) => ({ disk, region })));
  const createCapacity = createKind === "windows_partition"
    ? bytes(disks.find((disk) => String(disk.number) === createTarget)?.largestFreeExtentBytes ?? disks.find((disk) => String(disk.number) === createTarget)?.unallocatedBytes)
    : createKind === "linux_partition"
      ? bytes(freeRegions.find(({ disk, region }) => `${disk.path}|${region.startBytes}` === createTarget)?.region.sizeBytes)
      : createKind === "linux_lv"
        ? bytes(scan.volumeGroups.find((vg) => vg.name === createTarget)?.freeBytes)
        : bytes(scan.lvmCandidates.find((item) => item.path === createTarget)?.sizeBytes);
  const createMaxGiB = createCapacity > 0 ? Math.floor((createCapacity / 1024 ** 3) * 1000) / 1000 : 0;
  const deleteBlocked = Boolean(selected?.protected || (selected?.kind === "linux_vg" && selected.mounted));

  return (
    <section className="resource-tab storage-resource-tab">
      <div className="resource-toolbar">
        <div><h2>Disk & Volumes</h2><p>{osFamily === "windows" ? "Disk → partition → volume" : "Disk → partition → filesystem/LVM"}</p></div>
        <div className="resource-toolbar-actions">
          <button className="button ghost" type="button" onClick={refresh} disabled={busy}>↻ Quét lại</button>
          <button className="resource-icon-button add" type="button" onClick={() => { setCreateTarget(""); setModal("create"); }} title="Tạo partition, VG hoặc LV">+</button>
          <button className="resource-icon-button remove" type="button" disabled={!selected || deleteBlocked} onClick={() => setModal("delete")} title="Xóa mục đã chọn">−</button>
        </div>
      </div>
      <PendingState job={job} />
      <div className="storage-summary-grid">
        <div><b>{disks.length}</b><span>Disk</span></div>
        <div><b>{formatBytes(disks.reduce((sum, disk) => sum + bytes(disk.sizeBytes), 0))}</b><span>Tổng dung lượng</span></div>
        <div><b>{formatBytes(disks.reduce((sum, disk) => sum + bytes(disk.unallocatedBytes), 0))}</b><span>Unallocated</span></div>
        {osFamily === "linux" && <div><b>{scan.volumeGroups.length}</b><span>Volume Group</span></div>}
      </div>
      {windowsLayoutWarnings.length > 0 && <div className="storage-layout-warnings">
        {windowsLayoutWarnings.map((warning) => <div key={warning.key}><b>{warning.volume} chưa thể Extend</b><span>Disk {warning.disk} có {formatBytes(warning.freeBytes)} Unallocated ở phía sau, nhưng {warning.blockers} đang nằm giữa. Shrink không di chuyển phần đang chắn.</span></div>)}
      </div>}
      <div className="storage-tree">
        <div className="storage-tree-row head"><span /><span>Disk / partition / volume</span><span>Filesystem</span><span>Dung lượng</span><span>{osFamily === "windows" ? "Vị trí vật lý" : "Mount"}</span><span>Còn trống</span><span>Thao tác</span></div>
        {disks.map((disk, index) => {
          const key = String(disk.id ?? disk.path ?? disk.number ?? index);
          const children = osFamily === "windows" ? disk.partitions ?? [] : disk.children ?? [];
          return (
            <div className="storage-disk" key={key}>
              <div className="storage-tree-row disk-row">
                <span className="storage-tree-toggle"><button type="button" onClick={() => toggle(key)}>{expanded.includes(key) ? "⌄" : "›"}</button></span>
                <span className="storage-name"><b>{osFamily === "windows" ? `Disk ${disk.number}` : disk.path}</b><small>{disk.model || "Disk"} · {disk.partitionTable || "chưa có partition table"}</small></span>
                <span>{disk.partitionTable || "—"}</span><span>{formatBytes(disk.sizeBytes)}</span><span>—</span><span>{formatBytes(disk.unallocatedBytes)}</span><span />
              </div>
              {expanded.includes(key) && <div>
                {osFamily === "windows" && children.length > 0 && <div className="storage-disk-layout" aria-label={`Thứ tự vật lý các phân vùng trên Disk ${disk.number}`}>
                  {children.map((child, childIndex) => {
                    const segmentName = child.type === "unallocated" ? "Unallocated" : child.driveLetter ? `${child.driveLetter}:` : `P${child.partitionNumber ?? childIndex + 1}`;
                    const proportion = Math.max(0.5, bytes(child.sizeBytes) / Math.max(1, bytes(disk.sizeBytes)) * 100);
                    return <div className={child.type === "unallocated" ? "free" : child.protected ? "protected" : "volume"} style={{ flexGrow: proportion }} key={`layout-${child.id ?? childIndex}`} title={`${segmentName} · ${formatBytes(child.sizeBytes)} · offset ${formatBytes(child.offsetBytes)}`}><b>{segmentName}</b><small>{formatBytes(child.sizeBytes)}</small></div>;
                  })}
                </div>}
                {children.map((child) => renderNode(child, disk, 1))}
              </div>}
            </div>
          );
        })}
        {!disks.length && <div className="empty-state">Chưa có dữ liệu Disk; nhấn “Quét lại”.</div>}
      </div>
      <p className="storage-extend-note">Các hàng và thanh sơ đồ được xếp theo offset thật từ trái sang phải. Extend chỉ bật khi Agent xác nhận có vùng Unallocated liền ngay bên phải. Unallocated không thể kéo thả; Shrink tạo vùng trống ở cuối chính volume đó và không di chuyển partition khác. Nếu Recovery nằm giữa C: và vùng trống, cần một quy trình bảo trì riêng có backup để di chuyển hoặc xóa/tạo lại Recovery.</p>
      {osFamily === "linux" && scan.volumeGroups.length > 0 && <div className="vg-grid">
        {scan.volumeGroups.map((vg) => {
          const target: StorageTarget = { key: `vg:${vg.name}`, kind: "linux_vg", label: `Volume Group ${vg.name}`, name: vg.name, protected: false, mounted: vg.logicalVolumes.length > 0 };
          return <div key={vg.name} className={`vg-card ${selected?.key === target.key ? "selected" : ""}`}><label><span className="sr-only">Chọn Volume Group</span><input aria-label={`Chọn Volume Group ${vg.name}`} type="checkbox" checked={selected?.key === target.key} disabled={target.mounted} onChange={() => setSelected(selected?.key === target.key ? null : target)} /><span><b>{vg.name}</b><small>{vg.physicalVolumes.join(", ")}</small></span></label><span>{formatBytes(vg.sizeBytes)}<small>{formatBytes(vg.freeBytes)} còn trống</small></span></div>;
        })}
      </div>}

      {modal === "extend" && selected && <ModalShell title={`Extend ${selected.label}`} subtitle={`Dung lượng có thể dùng: ${formatBytes(selected.extendableBytes)}`} close={() => setModal(null)}>
        <form className="resource-form" onSubmit={submitExtend}>
          <label>Dung lượng thêm (GiB)<input name="size_gb" type="number" min="0.001" step="0.001" max={(bytes(selected.extendableBytes) / 1024 ** 3).toFixed(3)} required /></label>
          <div className="resource-help">Agent sẽ kiểm tra lại vùng trống liên tục/LVM free ngay trước khi mở rộng. Filesystem ext4/xfs và Windows volume được grow cùng partition.</div>
          <div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary" disabled={busy}>Extend</button></div>
        </form>
      </ModalShell>}

      {modal === "shrink" && selected?.kind === "windows_partition" && <ModalShell title={`Shrink ${selected.label}`} subtitle={`Có thể thu nhỏ tối đa theo lần quét này: ${formatBytes(selected.shrinkableBytes)}`} close={() => setModal(null)}>
        <form className="resource-form" onSubmit={submitShrink}>
          <label>Dung lượng cần thu nhỏ (GiB)<input name="size_gb" type="number" min="0.016" step="0.001" max={(bytes(selected.shrinkableBytes) / 1024 ** 3).toFixed(3)} required /></label>
          <div className="resource-help">Vùng Unallocated mới sẽ xuất hiện ngay bên phải volume này. Shrink không di chuyển Recovery hay bất kỳ partition nào, vì vậy không thể dùng Shrink để đưa vùng trống ở cuối Disk vượt qua Recovery về sát ổ C:.</div>
          <div className="danger-panel">Hãy bảo đảm đã có backup và không có tác vụ ghi dữ liệu lớn. Agent sẽ đọc lại SizeMin ngay trước khi resize và dừng nếu dung lượng an toàn đã thay đổi.</div>
          <div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary" disabled={busy}>Shrink</button></div>
        </form>
      </ModalShell>}

      {modal === "create" && <ModalShell title="Tạo storage mới" subtitle={osFamily === "windows" ? "Tạo partition và format volume" : "Tạo partition, Volume Group hoặc Logical Volume"} close={() => setModal(null)}>
        <form className="resource-form" onSubmit={submitCreate}>
          {osFamily === "linux" && <label>Loại cần tạo<select value={createKind} onChange={(event) => { setCreateKind(event.target.value); setCreateTarget(""); }}><option value="linux_partition">Partition + filesystem</option><option value="linux_vg">Volume Group từ partition trống</option><option value="linux_lv">Logical Volume trong VG</option></select></label>}
          {createKind === "windows_partition" && <>
            <label>Disk có unallocated space<select name="disk_number" value={createTarget} onChange={(event) => setCreateTarget(event.target.value)} required><option value="">Chọn Disk…</option>{disks.filter((disk) => bytes(disk.largestFreeExtentBytes ?? disk.unallocatedBytes) > 0 && !disk.readOnly).map((disk) => <option key={disk.number} value={disk.number}>Disk {disk.number} · vùng liên tục lớn nhất {formatBytes(disk.largestFreeExtentBytes ?? disk.unallocatedBytes)}</option>)}</select></label>
            <label>Dung lượng (GiB)<input name="size_gb" type="number" min="0.02" step="0.001" max={createMaxGiB || undefined} disabled={!createTarget} required /></label>
            <div className="resource-form-grid"><label>Filesystem<select name="filesystem"><option>NTFS</option><option>ReFS</option></select></label><label>Drive letter<input name="drive_letter" maxLength={1} pattern="[D-Zd-z]" placeholder="Tự động" /></label></div>
            <label>Nhãn volume<input name="label" defaultValue="New Volume" maxLength={32} required /></label>
          </>}
          {createKind === "linux_partition" && <>
            <label>Vùng unallocated quét từ server<select name="region" value={createTarget} onChange={(event) => setCreateTarget(event.target.value)} required><option value="">Chọn vùng trống…</option>{freeRegions.map(({ disk, region }) => <option key={`${disk.path}-${region.startBytes}`} value={`${disk.path}|${region.startBytes}`}>{disk.path} · {formatBytes(region.sizeBytes)} từ offset {formatBytes(region.startBytes)}</option>)}</select></label>
            <label>Dung lượng (GiB)<input name="size_gb" type="number" min="0.02" step="0.001" max={createMaxGiB || undefined} disabled={!createTarget} required /></label>
            <div className="resource-form-grid"><label>Filesystem<select name="filesystem"><option value="ext4">ext4</option><option value="xfs">xfs</option></select></label><label>Nhãn filesystem<input name="label" maxLength={32} /></label></div>
            <label>Mount point<input name="mount_point" pattern="/(mnt|srv|data|opt|var/lib)(/[A-Za-z0-9_.-]+)+" placeholder="/data/app" required /></label>
          </>}
          {createKind === "linux_vg" && <>
            <label>Partition trống<select name="device" value={createTarget} onChange={(event) => setCreateTarget(event.target.value)} required><option value="">Chọn partition…</option>{scan.lvmCandidates.map((item) => <option key={item.path} value={item.path}>{item.path} · {formatBytes(item.sizeBytes)}</option>)}</select></label>
            <label>Tên Volume Group<input name="name" pattern="[A-Za-z0-9_.+-]+" required /></label>
            <input name="size_gb" type="hidden" value="1" />
          </>}
          {createKind === "linux_lv" && <>
            <label>Volume Group<select name="vg_name" value={createTarget} onChange={(event) => setCreateTarget(event.target.value)} required><option value="">Chọn VG…</option>{scan.volumeGroups.filter((vg) => bytes(vg.freeBytes) > 0).map((vg) => <option key={vg.name} value={vg.name}>{vg.name} · còn {formatBytes(vg.freeBytes)}</option>)}</select></label>
            <label>Tên Logical Volume<input name="name" pattern="[A-Za-z0-9_.+-]+" required /></label>
            <label>Dung lượng (GiB)<input name="size_gb" type="number" min="0.02" step="0.001" max={createMaxGiB || undefined} disabled={!createTarget} required /></label>
            <div className="resource-form-grid"><label>Filesystem<select name="filesystem"><option value="ext4">ext4</option><option value="xfs">xfs</option></select></label><label>Nhãn filesystem<input name="label" maxLength={32} /></label></div>
            <label>Mount point<input name="mount_point" pattern="/(mnt|srv|data|opt|var/lib)(/[A-Za-z0-9_.-]+)+" placeholder="/data/app" required /></label>
          </>}
          <div className="resource-help">{createTarget ? `Dung lượng khả dụng vừa quét: ${formatBytes(createCapacity)}. ` : "Hãy chọn target lấy từ máy chủ để xem dung lượng khả dụng. "}Nếu layout thay đổi trước lúc chạy, Agent sẽ dừng thay vì ghi nhầm Disk.</div>
          <div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary" disabled={busy}>Tạo mới</button></div>
        </form>
      </ModalShell>}

      {modal === "delete" && selected && <ModalShell title={`Xóa ${selected.label}`} subtitle="Dữ liệu trên đối tượng này sẽ không thể khôi phục" close={() => setModal(null)}>
        <div className="resource-form"><div className="danger-panel">Agent từ chối xóa boot/system/root hoặc đối tượng đang chứa LV/partition con. Volume dữ liệu đang mount sẽ chỉ bị xóa nếu Agent unmount thành công.</div><label>Gõ <b>DELETE</b><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="off" /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button type="button" className="button danger" disabled={busy || confirmation !== "DELETE"} onClick={() => void submitDelete()}>Xóa</button></div></div>
      </ModalShell>}
    </section>
  );
}

type ServiceRow = { name: string; displayName?: string; status?: string; subState?: string; startType?: string; startsWithOs?: boolean };

export function ServicesResourceTab({ output, job, serverName, busy, refresh, queue }: { output?: string; job?: OperationJob; serverName: string; busy: boolean; refresh: () => void; queue: QueueOperation }) {
  const rows = useMemo(() => parseRows<ServiceRow>(output), [output]);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const filtered = rows.filter((row) => {
    const status = String(row.status ?? "").toLowerCase();
    const matchesStatus = filter === "all" || (filter === "running" ? ["running", "active"].includes(status) : filter === "stopped" ? ["stopped", "inactive", "dead"].includes(status) : !["running", "active", "stopped", "inactive", "dead"].includes(status));
    return matchesStatus && row.name.toLowerCase().includes(search.toLowerCase());
  });
  async function operate(action: string, name: string) {
    await queue(action, { name }, `${action} ${name} trên ${serverName}`);
  }
  return <section className="resource-tab">
    <div className="resource-toolbar"><div><h2>Services</h2><p>{rows.length} service quét trực tiếp từ hệ điều hành</p></div><div className="resource-toolbar-actions"><input className="resource-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Tìm service…" /><select value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">Tất cả trạng thái</option><option value="running">Running</option><option value="stopped">Stopped</option><option value="other">Khác / failed</option></select><button className="button ghost" onClick={refresh} disabled={busy}>↻</button></div></div>
    <PendingState job={job} />
    <div className="resource-table-scroll"><table className="resource-table services-resource-table"><thead><tr><th>Service</th><th>Trạng thái</th><th>Khởi động cùng OS</th><th>Thao tác</th></tr></thead><tbody>{filtered.map((service) => <tr key={service.name}><td><b>{service.name}</b></td><td><span className={`state-pill ${String(service.status).toLowerCase()}`}>{service.status || "unknown"}</span></td><td>{service.startsWithOs ? "Có" : "Không"}<small>{service.startType}</small></td><td><div className="inline-actions"><button type="button" disabled={busy || ["running", "active"].includes(String(service.status).toLowerCase())} onClick={() => void operate("service.start", service.name)}>Start</button><button type="button" disabled={busy || !["running", "active"].includes(String(service.status).toLowerCase())} onClick={() => void operate("service.stop", service.name)}>Stop</button><button type="button" disabled={busy} onClick={() => void operate("service.restart", service.name)}>Restart</button></div></td></tr>)}</tbody></table>{!rows.length && <div className="empty-state">Chưa có danh sách Services; nhấn nút quét lại.</div>}</div>
  </section>;
}

export type AccountUser = {
  name: string;
  enabled?: boolean;
  locked?: boolean;
  home?: string;
  shell?: string;
  groups?: string[];
  isAdmin?: boolean;
  protected?: boolean;
  accountExpires?: string;
  maxPasswordDays?: number | null;
};

export type AccountGroup = { name: string; members?: string[]; protected?: boolean };

export function AccountsResourceTab({
  userOutput,
  groupOutput,
  job,
  serverName,
  osFamily,
  busy,
  refresh,
  queue,
}: {
  userOutput?: string;
  groupOutput?: string;
  job?: OperationJob;
  serverName: string;
  osFamily: "windows" | "linux";
  busy: boolean;
  refresh: () => void;
  queue: QueueOperation;
}) {
  const users = useMemo(() => parseRows<AccountUser>(userOutput), [userOutput]);
  const groups = useMemo(() => parseRows<AccountGroup>(groupOutput), [groupOutput]);
  const [subtab, setSubtab] = useState<"users" | "groups">("users");
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [modal, setModal] = useState<"create-user" | "edit-user" | "create-group" | "delete-users" | "delete-groups" | null>(null);
  const [editing, setEditing] = useState<AccountUser | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [search, setSearch] = useState("");
  const [userState, setUserState] = useState<"all" | "active" | "disabled">("all");
  const visibleUsers = users.filter((user) => {
    const active = user.enabled !== false && !user.locked;
    return user.name.toLowerCase().includes(search.toLowerCase()) && (userState === "all" || (userState === "active" ? active : !active));
  });
  const visibleGroups = groups.filter((group) => group.name.toLowerCase().includes(search.toLowerCase()));
  const adminGroup = osFamily === "windows" ? "Administrators" : groups.some((group) => group.name === "sudo") ? "sudo" : "wheel";

  function toggleSelected(value: string, type: "users" | "groups") {
    if (type === "users") setSelectedUsers((current) => current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
    else setSelectedGroups((current) => current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
  }

  async function submitCreateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (!await queue("user.create", { username: form.get("username"), password: form.get("password"), groups: form.getAll("groups"), is_admin: form.get("is_admin") === "on" }, `Tạo user ${String(form.get("username"))} trên ${serverName}`)) return;
    setModal(null);
  }

  async function submitEditUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editing) return;
    const form = new FormData(event.currentTarget);
    const parameters: Record<string, unknown> = {
      username: editing.name,
      groups: form.getAll("groups"),
      is_admin: form.get("is_admin") === "on",
      enabled: form.get("enabled") === "on",
      unlock: form.get("unlock") === "on",
      account_expires: form.get("account_expires") ?? "",
    };
    if (form.get("password")) parameters.password = form.get("password");
    if (osFamily === "linux") parameters.max_password_days = Number(form.get("max_password_days") ?? -1);
    if (!await queue("user.update", parameters, `Cập nhật user ${editing.name} trên ${serverName}`)) return;
    setModal(null);
    setEditing(null);
  }

  async function submitCreateGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (!await queue("group.create", { group: form.get("group") }, `Tạo group ${String(form.get("group"))} trên ${serverName}`)) return;
    setModal(null);
  }

  async function submitDelete() {
    if (confirmation !== "DELETE") return;
    let succeeded = false;
    if (modal === "delete-users") {
      succeeded = await queue("user.delete", { usernames: selectedUsers }, `Xóa ${selectedUsers.length} user trên ${serverName}`);
      if (!succeeded) return;
      setSelectedUsers([]);
    } else {
      succeeded = await queue("group.delete", { groups: selectedGroups }, `Xóa ${selectedGroups.length} group trên ${serverName}`);
      if (!succeeded) return;
      setSelectedGroups([]);
    }
    setConfirmation("");
    setModal(null);
  }

  const groupChoices = groups.filter((group) => !group.protected || group.name === adminGroup);
  return <section className="resource-tab accounts-resource-tab">
    <div className="resource-toolbar"><div><h2>Users & Groups</h2><p>Tài khoản local và group lấy trực tiếp từ máy chủ</p></div><div className="resource-toolbar-actions"><input className="resource-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder={`Tìm ${subtab}…`} />{subtab === "users" && <select value={userState} onChange={(event) => setUserState(event.target.value as typeof userState)}><option value="all">Tất cả trạng thái</option><option value="active">Đang hoạt động</option><option value="disabled">Đã khóa / disable</option></select>}<button className="button ghost" onClick={refresh} disabled={busy}>↻</button><button className="resource-icon-button add" type="button" onClick={() => setModal(subtab === "users" ? "create-user" : "create-group")}>+</button><button className="resource-icon-button remove" type="button" disabled={subtab === "users" ? !selectedUsers.length : !selectedGroups.length} onClick={() => setModal(subtab === "users" ? "delete-users" : "delete-groups")}>−</button></div></div>
    <nav className="resource-subtabs"><button className={subtab === "users" ? "active" : ""} onClick={() => setSubtab("users")}>Users <span>{users.length}</span></button><button className={subtab === "groups" ? "active" : ""} onClick={() => setSubtab("groups")}>Groups <span>{groups.length}</span></button></nav>
    <PendingState job={job} />
    {subtab === "users" ? <div className="resource-table-scroll"><table className="resource-table"><thead><tr><th className="check-column" /><th>User</th><th>Trạng thái</th><th>Groups</th><th>Quyền quản trị</th></tr></thead><tbody>{visibleUsers.map((user) => <tr key={user.name} className={user.protected ? "protected" : "clickable"} onClick={() => { if (!user.protected) { setEditing(user); setModal("edit-user"); } }}><td onClick={(event) => event.stopPropagation()}><input type="checkbox" checked={selectedUsers.includes(user.name)} disabled={user.protected} onChange={() => toggleSelected(user.name, "users")} /></td><td><b>{user.name}</b><small>{user.home || user.shell || "Local user"}</small></td><td><span className={`state-pill ${user.enabled === false || user.locked ? "stopped" : "running"}`}>{user.enabled === false || user.locked ? "Đã khóa" : "Hoạt động"}</span></td><td>{user.groups?.slice(0, 5).join(", ") || "—"}{(user.groups?.length ?? 0) > 5 ? "…" : ""}</td><td>{user.isAdmin ? adminGroup : "Standard"}</td></tr>)}</tbody></table>{!users.length && <div className="empty-state">Chưa có dữ liệu Users.</div>}</div> : <div className="resource-table-scroll"><table className="resource-table"><thead><tr><th className="check-column" /><th>Group</th><th>Thành viên</th></tr></thead><tbody>{visibleGroups.map((group) => <tr key={group.name} className={group.protected ? "protected" : ""}><td><input type="checkbox" checked={selectedGroups.includes(group.name)} disabled={group.protected} onChange={() => toggleSelected(group.name, "groups")} /></td><td><b>{group.name}</b>{group.protected && <small>Group hệ thống được bảo vệ</small>}</td><td>{group.members?.slice(0, 8).join(", ") || "Không có thành viên trực tiếp"}</td></tr>)}</tbody></table>{!groups.length && <div className="empty-state">Chưa có dữ liệu Groups.</div>}</div>}

    {modal === "create-user" && <ModalShell title="Tạo user" subtitle={`${serverName} · ${osFamily}`} close={() => setModal(null)}><form className="resource-form" onSubmit={submitCreateUser}><label>Username<input name="username" pattern={osFamily === "linux" ? "[a-z_][a-z0-9_.-]{0,31}" : "[^\\/\\[\\]:;|=,+*?<>@]{1,20}"} maxLength={osFamily === "linux" ? 32 : 20} title={osFamily === "linux" ? "Bắt đầu bằng chữ thường hoặc _, sau đó dùng chữ thường, số, _, . hoặc -" : "Tên local Windows tối đa 20 ký tự và không chứa ký tự đặc biệt bị cấm"} required /></label><label>Mật khẩu ban đầu<input name="password" type="password" minLength={12} autoComplete="new-password" required /></label><fieldset><legend>Groups quét từ máy chủ</legend><div className="choice-grid">{groupChoices.map((group) => <label key={group.name}><input type="checkbox" name="groups" value={group.name} />{group.name}</label>)}</div></fieldset><label className="check"><input type="checkbox" name="is_admin" />Thêm quyền {adminGroup}</label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary" disabled={busy}>Tạo user</button></div></form></ModalShell>}
    {modal === "edit-user" && editing && <ModalShell title={`Chỉnh sửa ${editing.name}`} subtitle={`${osFamily === "windows" ? "Windows" : "Linux"} · mật khẩu, trạng thái, group và thời hạn`} close={() => { setModal(null); setEditing(null); }}><form className="resource-form" onSubmit={submitEditUser}><label>Mật khẩu mới (để trống nếu không đổi)<input name="password" type="password" minLength={12} autoComplete="new-password" /></label><div className="resource-form-grid"><label>Hết hạn tài khoản<input name="account_expires" type="date" defaultValue={/^\d{4}-\d{2}-\d{2}$/.test(editing.accountExpires ?? "") ? editing.accountExpires : ""} /></label>{osFamily === "linux" && <label>Tuổi mật khẩu tối đa (ngày)<input name="max_password_days" type="number" min="-1" max="99999" defaultValue={editing.maxPasswordDays ?? -1} /></label>}</div><fieldset><legend>Groups trên máy chủ</legend><div className="choice-grid">{groupChoices.map((group) => <label key={group.name}><input type="checkbox" name="groups" value={group.name} defaultChecked={editing.groups?.includes(group.name)} />{group.name}</label>)}</div></fieldset><div className="resource-form-grid checks"><label className="check"><input type="checkbox" name="enabled" defaultChecked={editing.enabled !== false && !editing.locked} />Enable tài khoản</label><label className="check"><input type="checkbox" name="is_admin" defaultChecked={editing.isAdmin} />Quyền {adminGroup}</label>{editing.locked && <label className="check"><input type="checkbox" name="unlock" defaultChecked />Unlock tài khoản</label>}</div><div className="resource-help">Bỏ/chọn group tại đây sẽ gỡ/thêm membership tương ứng. Agent đọc lại danh sách sau khi lưu để xác nhận trạng thái thực tế.</div><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary" disabled={busy}>Lưu thay đổi</button></div></form></ModalShell>}
    {modal === "create-group" && <ModalShell title="Tạo group" subtitle={serverName} close={() => setModal(null)}><form className="resource-form" onSubmit={submitCreateGroup}><label>Tên group<input name="group" pattern={osFamily === "linux" ? "[a-z_][a-z0-9_.-]{0,31}" : "[A-Za-z0-9_.@ -]{1,128}"} maxLength={osFamily === "linux" ? 32 : 128} required /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button className="button primary" disabled={busy}>Tạo group</button></div></form></ModalShell>}
    {(modal === "delete-users" || modal === "delete-groups") && <ModalShell title={`Xóa ${modal === "delete-users" ? selectedUsers.length + " user" : selectedGroups.length + " group"}`} subtitle="Thao tác trực tiếp và được ghi audit" close={() => setModal(null)}><div className="resource-form"><div className="danger-panel">{(modal === "delete-users" ? selectedUsers : selectedGroups).join(", ")}</div><label>Gõ <b>DELETE</b><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setModal(null)}>Hủy</button><button type="button" className="button danger" disabled={busy || confirmation !== "DELETE"} onClick={() => void submitDelete()}>Xóa</button></div></div></ModalShell>}
  </section>;
}

export type ProcessRow = { pid: number; name: string; created: number; username?: string; cpuPercent?: number; memoryPercent?: number; memoryBytes?: number };

export function ProcessesResourceTab({ output, job, serverName, busy, refresh, queue }: { output?: string; job?: OperationJob; serverName: string; busy: boolean; refresh: () => void; queue: QueueOperation }) {
  const rows = useMemo(() => parseRows<ProcessRow>(output), [output]);
  const [selected, setSelected] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [resourceFilter, setResourceFilter] = useState<"all" | "cpu" | "memory">("all");
  const [sort, setSort] = useState<{ column: "name" | "cpu" | "memory"; direction: "asc" | "desc" }>({ column: "cpu", direction: "desc" });
  const [live, setLive] = useState(true);
  useEffect(() => {
    if (!live || busy) return;
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [busy, live, refresh]);
  const filtered = rows
    .filter((process) => process.name.toLowerCase().includes(search.toLowerCase()))
    .filter((process) => resourceFilter === "all" || (resourceFilter === "cpu" ? Number(process.cpuPercent ?? 0) > 0 : Number(process.memoryBytes ?? 0) > 0))
    .sort((left, right) => {
      const multiplier = sort.direction === "asc" ? 1 : -1;
      if (sort.column === "name") return left.name.localeCompare(right.name, "vi") * multiplier;
      const leftValue = sort.column === "cpu" ? Number(left.cpuPercent ?? 0) : Number(left.memoryBytes ?? 0);
      const rightValue = sort.column === "cpu" ? Number(right.cpuPercent ?? 0) : Number(right.memoryBytes ?? 0);
      return (leftValue - rightValue || left.pid - right.pid) * multiplier;
    });
  function key(process: ProcessRow) { return `${process.pid}:${process.created}`; }
  function changeSort(column: typeof sort.column) {
    setSort((current) => ({ column, direction: current.column === column && current.direction === "desc" ? "asc" : "desc" }));
  }
  function sortMark(column: typeof sort.column) { return sort.column === column ? (sort.direction === "desc" ? " ↓" : " ↑") : ""; }
  async function terminate() {
    const processes = rows.filter((process) => selected.includes(key(process))).map((process) => ({ pid: process.pid, name: process.name, created: process.created }));
    if (!await queue("process.kill", { processes }, `Kill ${processes.length} process trên ${serverName}`)) return;
    setSelected([]); setConfirm(false);
  }
  return <section className="resource-tab"><div className="resource-toolbar"><div><h2>Processes</h2><p>{rows.length} process · CPU/RAM lấy trực tiếp từ máy chủ</p></div><div className="resource-toolbar-actions"><input className="resource-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Tìm process…" /><select value={resourceFilter} onChange={(event) => setResourceFilter(event.target.value as typeof resourceFilter)}><option value="all">Tất cả process</option><option value="cpu">Đang dùng CPU</option><option value="memory">Đang dùng RAM</option></select><label className="live-toggle"><input type="checkbox" checked={live} onChange={(event) => setLive(event.target.checked)} />Realtime 5s</label><button className="button ghost" onClick={refresh} disabled={busy}>↻</button><button className="button danger compact" disabled={!selected.length} onClick={() => setConfirm(true)}>Kill ({selected.length})</button></div></div><PendingState job={job} /><div className="resource-table-scroll process-list"><table className="resource-table"><thead><tr><th className="check-column" /><th><button className="table-sort" type="button" onClick={() => changeSort("name")}>Tên process{sortMark("name")}</button></th><th><button className="table-sort" type="button" onClick={() => changeSort("cpu")}>CPU %{sortMark("cpu")}</button></th><th><button className="table-sort" type="button" onClick={() => changeSort("memory")}>RAM{sortMark("memory")}</button></th></tr></thead><tbody>{filtered.map((process) => <tr key={key(process)}><td><input type="checkbox" checked={selected.includes(key(process))} onChange={() => setSelected((current) => current.includes(key(process)) ? current.filter((item) => item !== key(process)) : [...current, key(process)])} /></td><td><b>{process.name}</b><small>PID {process.pid}{process.username ? ` · ${process.username}` : ""}</small></td><td><b>{Number(process.cpuPercent ?? 0).toFixed(1)}%</b></td><td><b>{formatBytes(Number(process.memoryBytes ?? 0))}</b><small>{Number(process.memoryPercent ?? 0).toFixed(1)}%</small></td></tr>)}</tbody></table>{!rows.length && <div className="empty-state">Chưa có dữ liệu process.</div>}</div>{confirm && <ModalShell title={`Kill ${selected.length} process`} subtitle="Agent sẽ đối chiếu PID, tên và thời điểm tạo để tránh kill nhầm PID tái sử dụng" close={() => setConfirm(false)}><div className="resource-form"><div className="danger-panel">{rows.filter((process) => selected.includes(key(process))).map((process) => process.name).join(", ")}</div><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setConfirm(false)}>Hủy</button><button type="button" className="button danger" disabled={busy} onClick={() => void terminate()}>Kill process</button></div></div></ModalShell>}</section>;
}

export type UpdateRow = { id: string; revision?: number; name: string; version?: string; currentVersion?: string; architecture?: string; repository?: string; severity?: string; sizeBytes?: number; description?: string; kb?: string[]; rebootRequired?: boolean };

export function UpdatesResourceTab({ output, job, serverName, busy, refresh, queue }: { output?: string; job?: OperationJob; serverName: string; busy: boolean; refresh: () => void; queue: QueueOperation }) {
  const payload = useMemo(() => parseObject(output), [output]);
  const rows = objectArray(payload.updates) as UpdateRow[];
  const [selected, setSelected] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  async function install() {
    const updates = rows.filter((item) => selected.includes(item.id)).map((item) => ({ id: item.id, version: item.version ?? "", revision: item.revision ?? 0 }));
    if (!await queue("patch.install", { updates }, `Cài ${updates.length} update đã chọn trên ${serverName}`)) return;
    setSelected([]);
  }
  const emptyMessage = "Chưa có bản cập nhật khả dụng hoặc chưa quét dữ liệu; nhấn Quét lại.";
  return <section className="resource-tab updates-resource-tab">
    <div className="resource-toolbar"><div><h2>Updates</h2><p>{rows.length} bản cập nhật khả dụng · chỉ cài gói được chọn</p></div><div className="resource-toolbar-actions"><button className="button ghost" onClick={refresh} disabled={busy}>↻ Quét lại</button><button className="button primary compact" disabled={!selected.length || busy} onClick={() => void install()}>Cập nhật ({selected.length})</button></div></div>
    <PendingState job={job} />
    <div className="resource-table-scroll"><table className="resource-table updates-table"><thead><tr><th className="check-column"><input type="checkbox" checked={rows.length > 0 && rows.every((item) => selected.includes(item.id))} onChange={() => setSelected(rows.every((item) => selected.includes(item.id)) ? [] : rows.map((item) => item.id))} /></th><th>Gói / bản cập nhật</th><th>Phiên bản</th><th>Nguồn</th><th>Mức độ</th></tr></thead><tbody>{rows.map((update) => <Fragment key={update.id}><tr className="clickable" onClick={() => setExpanded(expanded === update.id ? null : update.id)}><td onClick={(event) => event.stopPropagation()}><input type="checkbox" checked={selected.includes(update.id)} onChange={() => setSelected((current) => current.includes(update.id) ? current.filter((item) => item !== update.id) : [...current, update.id])} /></td><td><b>{update.name}</b><small>{update.kb?.join(", ")}</small></td><td>{update.currentVersion ? `${update.currentVersion} → ` : ""}{update.version || "—"}</td><td>{update.repository || "—"}</td><td><span className={`state-pill ${update.severity === "security" || update.severity === "Critical" ? "warning" : ""}`}>{update.severity || "normal"}</span></td></tr>{expanded === update.id && <tr className="update-detail-row"><td /><td colSpan={4}><p>{update.description || "Không có mô tả chi tiết từ package manager."}</p><span>{update.architecture || ""}{update.sizeBytes ? ` · ${formatBytes(update.sizeBytes)}` : ""}{update.rebootRequired ? " · yêu cầu reboot" : ""}</span></td></tr>}</Fragment>)}</tbody></table>{!rows.length && <div className="empty-state">{emptyMessage}</div>}</div>
  </section>;
}

export type LogRow = { timestamp?: string; source: string; severity?: "error" | "warning" | "info"; message: string; id?: number; provider?: string };
export type LogSource = { id: string; label: string; type: string; records?: number };

export function LogsResourceTab({ output, sourceOutput, configured, job, serverName, busy, refresh, saveSources }: { output?: string; sourceOutput?: string; configured: string[]; job?: OperationJob; serverName: string; busy: boolean; refresh: () => void; saveSources: (sources: string[]) => Promise<boolean> }) {
  const rows = useMemo(() => parseRows<LogRow>(output), [output]);
  const sources = useMemo(() => parseRows<LogSource>(sourceOutput), [sourceOutput]);
  const [settings, setSettings] = useState(false);
  const [draft, setDraft] = useState<string[]>(configured);
  const [filter, setFilter] = useState("");
  const visible = rows.filter((row) => `${row.source} ${row.message}`.toLowerCase().includes(filter.toLowerCase()));
  async function save() { if (await saveSources(draft)) setSettings(false); }
  return <section className="resource-tab logs-resource-tab"><div className="resource-toolbar"><div><h2>System Logs</h2><p>Tối đa 500 dòng · {configured.length} nguồn log đã cấu hình</p></div><div className="resource-toolbar-actions"><input className="resource-search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Lọc nội dung log…" /><button className="button ghost" onClick={refresh} disabled={busy}>↻</button><button className="resource-icon-button settings" onClick={() => { setDraft(configured); setSettings(true); }} title="Cấu hình nguồn log">⚙</button></div></div><PendingState job={job} /><div className="log-viewer">{visible.map((row, index) => <div className={`log-line ${row.severity || "info"}`} key={`${row.timestamp}-${row.source}-${index}`}><time>{row.timestamp ? (row.timestamp.includes("T") ? new Date(row.timestamp).toLocaleString("vi-VN") : row.timestamp) : "—"}</time><b>{row.source}</b><span>{row.message}</span></div>)}{!rows.length && <div className="empty-state">Chưa có dữ liệu log; nhấn quét lại.</div>}</div>{settings && <ModalShell title="Nguồn log cần lấy" subtitle={`${serverName} · cấu hình lưu bền vững trong PostgreSQL`} close={() => setSettings(false)}><div className="resource-form"><fieldset><legend>Nguồn Agent quét được trên máy chủ</legend><div className="log-source-list">{sources.map((source) => <label key={source.id} aria-label={`Chọn nguồn log ${source.label}`}><input type="checkbox" checked={draft.includes(source.id)} disabled={!draft.includes(source.id) && draft.length >= 20} onChange={() => setDraft((current) => current.includes(source.id) ? current.filter((item) => item !== source.id) : [...current, source.id])} /><span><b>{source.label}</b><small>{source.type}</small></span></label>)}</div></fieldset><div className="resource-help">Linux chỉ cho chọn file thật dưới /var/log; Windows dùng Event Log channel đang bật. Agent kiểm tra lại nguồn trước khi đọc.</div><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setSettings(false)}>Hủy</button><button type="button" className="button primary" disabled={busy || !draft.length} onClick={() => void save()}>Lưu & lấy 500 dòng</button></div></div></ModalShell>}</section>;
}
