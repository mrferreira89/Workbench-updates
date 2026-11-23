/** Public catalog wire format and verification. No Workbench application code or credentials. */
import { createHash, createPublicKey, sign, verify } from "node:crypto";
export const FORMAT = "workbench-component-catalog/1";
export const CONTEXT = Buffer.from(`${FORMAT}\0`);
const CONTRACT = "workbench-chromium-cdp/1";
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");
function insist(condition, message) {
  if (!condition) throw new Error(message);
}
function id(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/.test(value);
}
function digest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}
// Keep publication within the native verifier's serde deny_unknown_fields
// contract: a valid signature does not make unsupported metadata usable.
function fields(value, names, label) {
  insist(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length === names.length &&
      names.every((name) => Object.hasOwn(value, name)),
    `Unsupported ${label} fields.`,
  );
}
function version(value, parts) {
  return (
    typeof value === "string" && new RegExp(`^[0-9]{1,8}(\\.[0-9]{1,8}){${parts - 1}}$`).test(value)
  );
}
export function validatePayload(payload) {
  fields(
    payload,
    [
      "format",
      "channel",
      "sequence",
      "issued_at",
      "expires_at",
      "components",
      "revoked_release_ids",
    ],
    "catalog",
  );
  insist(
    payload.format === 1 && payload.channel === "stable",
    "Unsupported catalog format or channel.",
  );
  insist(
    Number.isSafeInteger(payload.sequence) && payload.sequence > 0,
    "A positive catalog sequence is required.",
  );
  insist(
    Number.isSafeInteger(payload.issued_at) &&
      payload.issued_at >= 0 &&
      Number.isSafeInteger(payload.expires_at) &&
      payload.expires_at > payload.issued_at &&
      payload.expires_at - payload.issued_at <= 14 * 86400,
    "Catalog validity must be nonnegative and at most fourteen days.",
  );
  insist(
    Array.isArray(payload.components) &&
      payload.components.length === 1 &&
      Array.isArray(payload.revoked_release_ids) &&
      payload.revoked_release_ids.length <= 4096 &&
      payload.revoked_release_ids.every(id),
    "Each component feed must contain one registered component.",
  );
  const release = payload.components[0];
  fields(
    release,
    [
      "component",
      "id",
      "version",
      "source_commit",
      "recipe_sha256",
      "integration_contracts",
      "artifacts",
    ],
    "browser release",
  );
  insist(
    ["chromium", "imsg"].includes(release.component) &&
      id(release.id) &&
      version(release.version, release.component === "imsg" ? 3 : 4),
    "Invalid component release identity/version.",
  );
  const integration = release.component === "imsg" ? "workbench-imsg-applescript/1" : CONTRACT;
  insist(
    typeof release.source_commit === "string" &&
      /^[a-f0-9]{40}$/.test(release.source_commit) &&
      digest(release.recipe_sha256) &&
      Array.isArray(release.integration_contracts) &&
      release.integration_contracts.length <= 32 &&
      release.integration_contracts.every(
        (value) =>
          typeof value === "string" &&
          Buffer.byteLength(value) > 0 &&
          Buffer.byteLength(value) <= 128,
      ) &&
      release.integration_contracts.includes(integration),
    "A pinned source, recipe and supported integration contract are required.",
  );
  insist(
    Array.isArray(release.artifacts) &&
      release.artifacts.length === 2 &&
      ["mac-arm64", "mac-x64"].every(
        (platform) => release.artifacts.filter((a) => a?.platform === platform).length === 1,
      ),
    "Both Mac architectures are required exactly once.",
  );
  for (const artifact of release.artifacts) {
    fields(
      artifact,
      ["platform", "min_macos", "path", "bytes", "unpacked_bytes_max", "sha256"],
      "artifact",
    );
    insist(
      typeof artifact.path === "string" &&
        artifact.path.length <= 240 &&
        artifact.path
          .split("/")
          .every((s) => s && s !== "." && s !== ".." && /^[A-Za-z0-9._-]+$/.test(s)) &&
        artifact.path.endsWith(".zip"),
      "Unsafe artifact path.",
    );
    insist(
      digest(artifact.sha256) &&
        version(artifact.min_macos, 2) &&
        Number.isSafeInteger(artifact.bytes) &&
        artifact.bytes > 0 &&
        artifact.bytes <= 2 ** 30 &&
        Number.isSafeInteger(artifact.unpacked_bytes_max) &&
        artifact.unpacked_bytes_max >= artifact.bytes &&
        artifact.unpacked_bytes_max <= 2 ** 32,
      "Invalid artifact limits or digest.",
    );
  }
  return payload;
}
export function envelope(payload, key) {
  validatePayload(payload);
  const publicKey = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
  const bytes = Buffer.from(JSON.stringify(payload));
  return {
    format: FORMAT,
    key_id: sha256(publicKey).slice(0, 16),
    payload: bytes.toString("base64"),
    signature: sign(null, Buffer.concat([CONTEXT, bytes]), key).toString("base64"),
  };
}
export function verifyCatalog(bytes, config) {
  insist(bytes.length <= 2 << 20, "Catalog is too large.");
  const wrapper = JSON.parse(bytes.toString());
  fields(wrapper, ["format", "key_id", "payload", "signature"], "signed envelope");
  insist(wrapper.format === FORMAT, "Unknown signed envelope format.");
  const key = config.keys.find((k) => k.id === wrapper.key_id);
  insist(key, "Untrusted update signing key.");
  const publicKey = createPublicKey({
    format: "der",
    type: "spki",
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(key.public_key, "base64"),
    ]),
  });
  const payload = Buffer.from(wrapper.payload, "base64");
  insist(
    verify(
      null,
      Buffer.concat([CONTEXT, payload]),
      publicKey,
      Buffer.from(wrapper.signature, "base64"),
    ),
    "Invalid catalog signature.",
  );
  return validatePayload(JSON.parse(payload.toString()));
}

export function freshCatalog(payload, now = Math.floor(Date.now() / 1000)) {
  insist(
    payload.issued_at <= now + 300 && payload.expires_at > now,
    "The catalog is expired or from the future; refresh it before publishing or bundling.",
  );
  return payload;
}

/** Renew metadata without changing the previously qualified browser. An expired
 * authentic feed can be renewed; artifact identity and revocations cannot reset.
 */
export function refreshCatalog(
  previous,
  { sequence, issuedAt = Math.floor(Date.now() / 1000), revoked = [] },
) {
  validatePayload(previous);
  insist(
    sequence > previous.sequence && issuedAt >= previous.issued_at,
    "Catalog sequence must increase and its issue time cannot move backwards.",
  );
  insist(Array.isArray(revoked) && revoked.every(id), "Revocations must be a list of release IDs.");
  return validatePayload({
    ...previous,
    sequence,
    issued_at: issuedAt,
    expires_at: issuedAt + 14 * 86400,
    revoked_release_ids: [...new Set([...previous.revoked_release_ids, ...revoked])],
  });
}
