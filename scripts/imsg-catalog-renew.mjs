#!/usr/bin/env node
/** Public update infrastructure only: renew signed metadata for an existing
 * qualified release. No app source, Keychain access or software selection. */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  validatePayload,
  envelope,
  verifyCatalog,
  refreshCatalog,
  sha256,
} from "./component-catalog.mjs";
function insist(value, message) {
  if (!value) throw new Error(message);
}
function run(program, args) {
  const result = spawnSync(program, args, { encoding: "utf8", maxBuffer: 4 << 20, timeout: 60000 });
  insist(result.status === 0, `${program} failed; catalog publication stopped.`);
  return result.stdout;
}
function githubJson(path) {
  return JSON.parse(run("gh", ["api", path]));
}
export function githubRepository(config) {
  const match =
    /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/releases\/download$/.exec(
      config.artifact_base ?? "",
    );
  insist(
    match && config.catalog_url === `${config.artifact_base}/imsg-component-feed/catalog.json`,
    "A public helper release repository is required.",
  );
  return match[1];
}
export function signCatalog(
  payloadPath,
  config,
  secret = process.env.WORKBENCH_COMPONENT_SIGNING_KEY,
) {
  const payload = validatePayload(JSON.parse(readFileSync(payloadPath, "utf8")));
  insist(typeof secret === "string", "The protected CI signing authority is not configured.");
  const seed = Buffer.from(secret, "base64");
  insist(
    seed.length === 32 && seed.toString("base64") === secret,
    "The CI signing authority is invalid.",
  );
  const key = createPrivateKey({
    format: "der",
    type: "pkcs8",
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  });
  const publicKey = createPublicKey(key)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
  const pinned = config.keys.find((item) => item.public_key === publicKey);
  insist(pinned, "The CI authority does not match the compiled catalog public key.");
  const signed = envelope(payload, key);
  signed.key_id = pinned.id;
  const bytes = Buffer.from(JSON.stringify(signed));
  verifyCatalog(bytes, config);
  return bytes;
}
/** Renew an already published qualified release; never select new software. */
export function renewApprovedCatalog(
  config,
  output,
  { execute = run, github = githubJson, signer = signCatalog } = {},
) {
  const repository = githubRepository(config),
    tag = "imsg-component-feed";
  insist(
    config.catalog_url.endsWith(`/${tag}/catalog.json`),
    "Messages renewal requires the separate helper feed.",
  );
  const metadata = github(`repos/${repository}`);
  insist(metadata.private === false, "The existing artifact host must be public.");
  const readHead = () =>
    Buffer.from(
      execute("gh", [
        "release",
        "download",
        tag,
        "--repo",
        repository,
        "--pattern",
        "catalog.json",
        "--output",
        "-",
      ]),
    );
  const previousBytes = readHead(),
    previous = verifyCatalog(previousBytes, config);
  insist(
    previous.components[0].component === "imsg",
    "The published feed belongs to a different component.",
  );
  const release = previous.components[0];
  const artifacts = github(`repos/${repository}/releases/tags/${release.id}`);
  insist(!artifacts.draft, "Published helper artifacts are not publicly available.");
  for (const artifact of release.artifacts) {
    const asset = artifacts.assets.find((item) => item.name === `${artifact.platform}.zip`);
    insist(
      asset?.size === artifact.bytes && asset?.digest === `sha256:${artifact.sha256}`,
      "A published helper asset no longer matches its approved catalog.",
    );
  }
  const payload = refreshCatalog(previous, { sequence: previous.sequence + 1 });
  mkdirSync(dirname(output), { recursive: true });
  mkdirSync(output, { recursive: false });
  const payloadPath = join(output, "payload.json"),
    catalogPath = join(output, "catalog.json");
  writeFileSync(payloadPath, JSON.stringify(payload), { flag: "wx" });
  const signed = signer(payloadPath, config);
  insist(
    JSON.stringify(verifyCatalog(signed, config)) === JSON.stringify(payload),
    "Renewal changed the authenticated catalog.",
  );
  writeFileSync(catalogPath, signed, { flag: "wx" });
  insist(
    sha256(readHead()) === sha256(previousBytes),
    "Another release changed the feed during renewal; retry from the current signed catalog.",
  );
  execute("gh", [
    "release",
    "upload",
    tag,
    `${catalogPath}#catalog.json`,
    "--repo",
    repository,
    "--clobber",
  ]);
  insist(sha256(readHead()) === sha256(signed), "Renewed catalog readback did not match.");
  return { release: release.id, sequence: payload.sequence, softwareChanged: false };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    insist(
      args.length === 4 && args[0] === "--config" && args[2] === "--out",
      "Use --config public-config.json --out new-directory.",
    );
    const config = JSON.parse(readFileSync(args[1], "utf8"));
    insist(
      !process.env.GITHUB_REPOSITORY || process.env.GITHUB_REPOSITORY === githubRepository(config),
      "Run renewal in the public update repository; private app source is not required.",
    );
    console.log(JSON.stringify(renewApprovedCatalog(config, resolve(args[3]))));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
