#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const VERSION = "0.1.0";
const TOOL = "tutela";
const SOURCE = "github:kemiller2002/tutela";
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const payloads = [
  ["README.md", ".tutela/README.md"],
  ["security/SECURITY-PROFILE.md", ".tutela/SECURITY-PROFILE.md"],
  ["schemas/security-invariant.schema.json", ".tutela/schemas/security-invariant.schema.json"],
  ["schemas/threat.schema.json", ".tutela/schemas/threat.schema.json"],
  ["schemas/evidence.schema.json", ".tutela/schemas/evidence.schema.json"],
  ["schemas/security-assessment.schema.json", ".tutela/schemas/security-assessment.schema.json"],
  ["schemas/exception.schema.json", ".tutela/schemas/exception.schema.json"]
];

const regionStart = "<!-- echelon:tutela:start -->";
const regionEnd = "<!-- echelon:tutela:end -->";
const agentRegion = [
  regionStart,
  "## Tutela security engineering",
  "",
  "Tutela is installed as the repository security-engineering discipline.",
  "Before making or changing a security claim, read:",
  "",
  "- `.tutela/README.md`",
  "- `.tutela/SECURITY-PROFILE.md`",
  "- the applicable schema under `.tutela/schemas/`",
  "",
  "Security claims are evidence-scoped. Unknown security effects remain unknown,",
  "self-certification is not sufficient evidence, and an unsupported claim must",
  "not be upgraded to a passing release posture.",
  regionEnd
].join("\n");

const normalize = value => value.replace(/\r\n/g, "\n");
const sha256 = value => crypto.createHash("sha256").update(normalize(value), "utf8").digest("hex");
const readText = file => fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;

function rootFrom(argv) {
  const index = argv.indexOf("--root");
  if (index >= 0) {
    if (!argv[index + 1]) throw new Error("--root requires a path");
    return path.resolve(argv[index + 1]);
  }
  return process.cwd();
}

function manifestPath(root) {
  return path.join(root, ".echelon", "tutela.json");
}

function desiredPayload() {
  return payloads.map(([source, target]) => {
    const content = normalize(fs.readFileSync(path.join(packageRoot, source), "utf8"));
    return { source, target, content, sha256: sha256(content) };
  });
}

function extractRegion(text) {
  const start = text.indexOf(regionStart);
  const end = text.indexOf(regionEnd);
  if (start < 0 && end < 0) return null;
  if (start < 0 || end < start) return { malformed: true };
  return { start, end: end + regionEnd.length, text: text.slice(start, end + regionEnd.length) };
}

function desiredManifest(payload) {
  const artifacts = payload.map(item => ({
    path: item.target,
    ownership: "tool-owned",
    sha256: item.sha256
  }));
  artifacts.push({
    path: "AGENTS.md#tutela-region",
    ownership: "shared-region",
    sha256: sha256(agentRegion)
  });
  artifacts.sort((a, b) => a.path.localeCompare(b.path));
  return {
    schemaVersion: 1,
    tool: TOOL,
    source: SOURCE,
    installedVersion: VERSION,
    mode: "fail-closed",
    unknownSecurityEffectsBlockRelease: true,
    selfCertificationAllowed: false,
    securityClaim: "evidence-scoped",
    managedArtifacts: artifacts
  };
}

function readManifest(root) {
  const file = manifestPath(root);
  if (!fs.existsSync(file)) return { value: null };
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    if (value.schemaVersion !== 1 || value.tool !== TOOL) {
      return { error: "Tutela installation manifest uses an unsupported schema or tool id." };
    }
    return { value };
  } catch (error) {
    return { error: `Tutela installation manifest is unreadable: ${error.message}` };
  }
}

function ensureParent(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
}

function writeAtomic(file, content) {
  ensureParent(file);
  const temporary = `${file}.tutela-${process.pid}.tmp`;
  fs.writeFileSync(temporary, content, "utf8");
  fs.renameSync(temporary, file);
}

function planned(root, requireInstalled) {
  const existingResult = readManifest(root);
  if (existingResult.error) return { fatal: existingResult.error };
  if (requireInstalled && !existingResult.value) return { fatal: "Tutela is not installed; run init first." };

  const payload = desiredPayload();
  const recorded = new Map((existingResult.value?.managedArtifacts ?? []).map(item => [item.path, item]));
  const changes = [];
  const conflicts = [];

  for (const item of payload) {
    const file = path.join(root, item.target);
    const current = readText(file);
    if (current === null) {
      changes.push({ kind: "create", path: item.target, content: item.content });
    } else if (sha256(current) !== item.sha256) {
      const previous = recorded.get(item.target);
      if (previous && previous.sha256 === sha256(current)) {
        changes.push({ kind: "update", path: item.target, content: item.content });
      } else {
        conflicts.push({ code: "TUTELA004", path: item.target, message: "managed Tutela content has local changes" });
      }
    }
  }

  const agentsPath = path.join(root, "AGENTS.md");
  const agents = readText(agentsPath) ?? "";
  const region = extractRegion(agents);
  const previousRegion = recorded.get("AGENTS.md#tutela-region");

  if (region?.malformed) {
    conflicts.push({ code: "TUTELA005", path: "AGENTS.md", message: "Tutela managed region is malformed" });
  } else if (!region) {
    const prefix = agents.length === 0 ? "" : (agents.endsWith("\n") ? "\n" : "\n\n");
    changes.push({ kind: "register-agent-guidance", path: "AGENTS.md", content: agents + prefix + agentRegion + "\n" });
  } else if (sha256(region.text) !== sha256(agentRegion)) {
    if (previousRegion && previousRegion.sha256 === sha256(region.text)) {
      changes.push({
        kind: "update-agent-guidance",
        path: "AGENTS.md",
        content: agents.slice(0, region.start) + agentRegion + agents.slice(region.end)
      });
    } else {
      conflicts.push({ code: "TUTELA006", path: "AGENTS.md", message: "Tutela managed region has local changes" });
    }
  }

  const manifest = desiredManifest(payload);
  const manifestText = JSON.stringify(manifest, null, 2) + "\n";
  const currentManifest = readText(manifestPath(root));
  if (currentManifest === null || normalize(currentManifest) !== manifestText) {
    changes.push({ kind: currentManifest === null ? "write-manifest" : "update-manifest", path: ".echelon/tutela.json", content: manifestText });
  }

  return { payload, manifest, changes, conflicts };
}

function verify(root, strict) {
  const result = readManifest(root);
  if (result.error) return [{ code: "TUTELA002", severity: "error", message: result.error }];
  if (!result.value) return [{ code: "TUTELA001", severity: "error", message: "Tutela is not installed" }];

  const problems = [];
  const payload = desiredPayload();

  for (const item of payload) {
    const current = readText(path.join(root, item.target));
    if (current === null) {
      problems.push({ code: "TUTELA003", severity: "error", path: item.target, message: "managed Tutela content is missing" });
    } else if (sha256(current) !== item.sha256) {
      problems.push({ code: "TUTELA004", severity: strict ? "error" : "warning", path: item.target, message: "managed Tutela content differs from this version" });
    }
  }

  const agents = readText(path.join(root, "AGENTS.md"));
  const region = agents === null ? null : extractRegion(agents);
  if (!region || region.malformed) {
    problems.push({ code: "TUTELA005", severity: "error", path: "AGENTS.md", message: "Tutela managed agent guidance is missing or malformed" });
  } else if (sha256(region.text) !== sha256(agentRegion)) {
    problems.push({ code: "TUTELA006", severity: strict ? "error" : "warning", path: "AGENTS.md", message: "Tutela managed agent guidance differs from this version" });
  }

  if (strict && result.value.installedVersion !== VERSION) {
    problems.push({ code: "TUTELA007", severity: "error", message: `installed version ${result.value.installedVersion} does not match CLI ${VERSION}` });
  }

  return problems;
}

function emit(value, asJson) {
  if (asJson) {
    process.stdout.write(JSON.stringify(value, null, 2) + "\n");
    return;
  }
  if (value.message) console.log(value.message);
  for (const change of value.changes ?? []) console.log(`${change.kind}: ${change.path}`);
  for (const problem of value.problems ?? []) console.log(`${problem.severity ?? "error"} ${problem.code}: ${problem.path ? problem.path + ": " : ""}${problem.message}`);
  for (const conflict of value.conflicts ?? []) console.error(`${conflict.code} ${conflict.path}: ${conflict.message}`);
}

function main(argv) {
  if (argv.includes("--version")) {
    console.log(VERSION);
    return 0;
  }

  const command = argv[0];
  if (!["init", "upgrade", "verify", "doctor", "status"].includes(command)) {
    console.error("usage: tutela <init|upgrade|verify|doctor|status> [--root PATH] [--strict] [--json] [--dry-run]");
    return 2;
  }

  const root = rootFrom(argv);
  const asJson = argv.includes("--json");
  const strict = argv.includes("--strict");
  const dryRun = argv.includes("--dry-run");

  if (command === "status") {
    const manifest = readManifest(root);
    if (manifest.error) {
      emit({ schemaVersion: 1, command, state: "invalid", message: manifest.error }, asJson);
      return 4;
    }
    if (!manifest.value) {
      emit({ schemaVersion: 1, command, state: "not-installed", cliVersion: VERSION }, asJson);
      return 4;
    }
    const problems = verify(root, false);
    emit({ schemaVersion: 1, command, state: problems.some(p => p.severity === "error") ? "invalid" : "installed", installedVersion: manifest.value.installedVersion, cliVersion: VERSION, problems }, asJson);
    return problems.some(p => p.severity === "error") ? 3 : 0;
  }

  if (command === "verify" || command === "doctor") {
    const problems = verify(root, command === "verify" && strict);
    const failed = problems.some(problem => problem.severity === "error");
    emit({ schemaVersion: 1, command, ok: !failed, strict: command === "verify" && strict, problems, message: failed ? "Tutela verification failed." : "Tutela verification passed." }, asJson);
    return failed ? 3 : 0;
  }

  const plan = planned(root, command === "upgrade");
  if (plan.fatal) {
    emit({ schemaVersion: 1, command, failure: plan.fatal }, asJson);
    return 4;
  }
  if (plan.conflicts.length > 0) {
    emit({ schemaVersion: 1, command, applied: false, conflicts: plan.conflicts, changes: plan.changes.map(({content, ...rest}) => rest) }, asJson);
    return 5;
  }
  if (dryRun) {
    emit({ schemaVersion: 1, command, applied: false, changed: plan.changes.length > 0, conflicts: [], changes: plan.changes.map(({content, ...rest}) => rest) }, asJson);
    return 0;
  }

  for (const change of plan.changes) {
    writeAtomic(path.join(root, change.path), change.content);
  }

  const problems = verify(root, true);
  const failed = problems.some(problem => problem.severity === "error");
  emit({ schemaVersion: 1, command, applied: true, changed: plan.changes.length > 0, verification: { ok: !failed, problems }, message: failed ? "Tutela changed but strict verification failed." : "Tutela is installed and verified." }, asJson);
  return failed ? 3 : 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(`ERROR ${error.message}`);
  process.exitCode = 1;
}
