import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative } from "node:path";

const projectRoot = process.cwd();
const ignoredNames = new Set([".git", ".next", ".vinext", ".wrangler", "node_modules", "recordings", "work", "outputs"]);
const roots = ["app", "build", "public", "types", "worker", "Dockerfile", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "tsconfig.json", "vite.config.ts"];

function sourceFiles(path) {
  const entries = readdirSync(path, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
  return entries.flatMap((entry) => {
    if (ignoredNames.has(entry.name) || entry.name === "build-info.json") return [];
    const child = join(path, entry.name);
    return entry.isDirectory() ? sourceFiles(child) : [child];
  });
}

const suppliedRevision = (process.env.SOURCE_REVISION ?? "").trim();
let buildId = suppliedRevision;
if (!/^[A-Za-z0-9._-]{7,64}$/.test(buildId)) {
  const hash = createHash("sha256");
  for (const root of roots) {
    const absolute = join(projectRoot, root);
    const files = statSync(absolute).isDirectory() ? sourceFiles(absolute) : [absolute];
    for (const file of files) {
      hash.update(relative(projectRoot, file).replaceAll("\\", "/"));
      hash.update("\0");
      hash.update(readFileSync(file));
      hash.update("\0");
    }
  }
  buildId = `src-${hash.digest("hex").slice(0, 16)}`;
}

writeFileSync(join(projectRoot, "public", "build-info.json"), `${JSON.stringify({ buildId, builtAt: new Date().toISOString() })}\n`, "utf8");
const cli = join(projectRoot, "node_modules", "vinext", "dist", "cli.js");
const result = spawnSync(process.execPath, [cli, "build"], {
  cwd: projectRoot,
  env: { ...process.env, TRAM_BUILD_ID: buildId },
  stdio: "inherit",
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);