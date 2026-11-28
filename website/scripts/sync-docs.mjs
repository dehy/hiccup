// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copies the repository's Markdown documentation into Starlight's content
// directory. The files in the repository stay the single source of truth, and
// GitHub keeps rendering them as they are. For each page this script:
//   - turns the first `# Heading` into the `title` frontmatter,
//   - points "Edit page" at the source file on GitHub,
//   - rewrites links: to another synced page, to that page on the site;
//     to any other file of the repository, to GitHub.

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, posix, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_URL = "https://github.com/dehy/hiccup";
const BRANCH = "main";
const BASE = "/hiccup/";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const out = join(here, "..", "src", "content", "docs", "docs");

// Repository path → page slug under /docs/.
const pages = new Map([
  ["docs/getting-started.md", "getting-started"],
  ["docs/building.md", "building"],
  ["docs/ca.md", "ca"],
  ["docs/cli.md", "cli"],
  ["docs/control-api.md", "control-api"],
  ["docs/ai-agents.md", "ai-agents"],
  ["docs/architecture.md", "architecture"],
  ["ROADMAP.md", "roadmap"],
  ["CHANGELOG.md", "changelog"],
  ["CONTRIBUTING.md", "contributing"],
  ["SECURITY.md", "security"],
  ["docs/releasing.md", "releasing"],
]);
for (const file of readdirSync(join(root, "docs", "adr")).sort()) {
  if (file.endsWith(".md")) pages.set(`docs/adr/${file}`, `adr/${file.slice(0, -3)}`);
}
// Directories that have a page of their own.
const dirPages = new Map([["docs/adr", "adr"]]);

const pageUrl = (slug) => `${BASE}docs/${slug}/`;

function rewriteTarget(target, from) {
  if (/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(target)) return target;
  const [path, hash] = target.split("#", 2);
  const anchor = hash === undefined ? "" : `#${hash}`;
  if (path === "") return target;
  const resolved = posix.normalize(posix.join(posix.dirname(from), path)).replace(/\/$/, "");
  if (pages.has(resolved)) return pageUrl(pages.get(resolved)) + anchor;
  if (dirPages.has(resolved)) return pageUrl(dirPages.get(resolved)) + anchor;
  const abs = join(root, normalize(resolved));
  if (!existsSync(abs)) throw new Error(`${from}: broken link to ${target}`);
  const kind = statSync(abs).isDirectory() ? "tree" : "blob";
  return `${REPO_URL}/${kind}/${BRANCH}/${resolved}${anchor}`;
}

const ASIDES = { NOTE: "note", TIP: "tip", IMPORTANT: "note", WARNING: "caution", CAUTION: "danger" };

// `> [!WARNING]` followed by quoted lines becomes `:::caution` … `:::`.
function githubAlertsToAsides(text) {
  const lines = text.split("\n");
  const result = [];
  for (let i = 0; i < lines.length; i++) {
    const kind = /^> \[!([A-Z]+)\]$/.exec(lines[i].trimEnd())?.[1];
    if (!ASIDES[kind]) {
      result.push(lines[i]);
      continue;
    }
    const inner = [];
    while (lines[i + 1]?.startsWith(">")) inner.push(lines[++i].replace(/^> ?/, ""));
    while (inner.at(-1) === "") inner.pop();
    result.push(`:::${ASIDES[kind]}`, ...inner, ":::");
  }
  return result.join("\n");
}

function convert(source, from) {
  const lines = source.split("\n");
  const h1 = lines.findIndex((line) => line.trim() !== "");
  if (!lines[h1]?.startsWith("# ")) throw new Error(`${from}: the first line must be a # heading`);
  const title = lines[h1].slice(2).trim().replaceAll("`", "");
  let start = h1 + 1;
  while (lines[start] === "") start++;
  let body = lines.slice(start).join("\n");

  // Outside fenced code blocks: rewrite links, and turn GitHub alerts
  // (`> [!WARNING]` blockquotes) into Starlight asides.
  body = body
    .split(/(^```[\s\S]*?^```)/m)
    .map((part, i) =>
      i % 2 === 1
        ? part
        : githubAlertsToAsides(part).replace(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewriteTarget(target, from)})`),
    )
    .join("");

  const editUrl = `${REPO_URL}/edit/${BRANCH}/${from}`;
  const front = [
    "---",
    `title: ${JSON.stringify(title)}`,
    `editUrl: ${JSON.stringify(editUrl)}`,
    ...(from.startsWith("docs/adr/")
      ? ["sidebar:", `  label: ${JSON.stringify(title.replace(/^ADR (\d+):\s*/, "$1 "))}`]
      : []),
    "---",
    "",
  ].join("\n");
  return front + body;
}

rmSync(out, { recursive: true, force: true });
for (const [from, slug] of pages) {
  const target = join(out, `${slug}.md`);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, convert(readFileSync(join(root, from), "utf8"), from));
}

// An index of the decision records, built from their titles.
const adrs = [...pages]
  .filter(([from]) => from.startsWith("docs/adr/"))
  .map(([from, slug]) => {
    const lines = readFileSync(join(root, from), "utf8").split("\n");
    const title = lines.find((l) => l.startsWith("# ")).slice(2).replace(/^ADR \d+: */, "");
    const statusLine = lines.find((l) => l.includes("**Status:**")) ?? "";
    const status = statusLine.slice(statusLine.indexOf("**Status:**") + "**Status:**".length).trim();
    const number = slug.slice("adr/".length, "adr/".length + 4);
    const linkedStatus = status.replaceAll(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewriteTarget(target, from)})`);
    return `| [${number}](${pageUrl(slug)}) | ${title} | ${linkedStatus} |`;
  });
writeFileSync(
  join(out, "adr", "index.md"),
  [
    "---",
    'title: "Architecture decision records"',
    `editUrl: false`,
    "sidebar:",
    '  label: "All decisions"',
    "  order: 0",
    "---",
    "",
    "Each significant decision about Hiccup's architecture is recorded here, with its context and consequences. To propose a change, open an issue labelled `type:roadmap` and add a new record.",
    "",
    "| ADR | Decision | Status |",
    "| --- | --- | --- |",
    ...adrs,
    "",
  ].join("\n"),
);

console.log(`synced ${pages.size} pages into ${relative(process.cwd(), out)}`);
