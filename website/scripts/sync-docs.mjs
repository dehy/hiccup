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

function githubAlertsToAsides(text) {
  return text.replace(
    /^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*\n((?:>.*(?:\n|$))*)/gm,
    (_, kind, quoted) => {
      const inner = quoted.replace(/^> ?/gm, "").replace(/\n+$/, "");
      return `:::${ASIDES[kind]}\n${inner}\n:::\n`;
    },
  );
}

function convert(source, from) {
  const lines = source.split("\n");
  const h1 = lines.findIndex((line) => line.trim() !== "");
  const match = /^#\s+(.+?)\s*$/.exec(lines[h1] ?? "");
  if (!match) throw new Error(`${from}: the first line must be a # heading`);
  const title = match[1].replace(/`/g, "");
  let body = lines.slice(h1 + 1).join("\n").replace(/^\n+/, "");

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

  const front = [
    "---",
    `title: ${JSON.stringify(title)}`,
    `editUrl: ${JSON.stringify(`${REPO_URL}/edit/${BRANCH}/${from}`)}`,
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
    const head = readFileSync(join(root, from), "utf8").split("\n").find((l) => l.startsWith("# "));
    const status = /\*\*Status:\*\*\s*([^\n]+)/.exec(readFileSync(join(root, from), "utf8"))?.[1] ?? "";
    const title = head.slice(2).replace(/^ADR \d+:\s*/, "");
    return `| [${from.match(/(\d{4})/)[1]}](${pageUrl(slug)}) | ${title} | ${status.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")} |`;
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
