# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first: it lists the checks every pull request must pass, the commit format and the DCO sign-off.

## Keep the documentation and the website up to date

Every pull request updates the documentation it makes out of date, in the same pull request. A change is not done while the docs describe the old behaviour.

- **Docs.** The Markdown in `docs/` and the root (`README.md`, `ROADMAP.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`) is the single source. The website copies it at build time, so fix the Markdown, never the generated pages in `website/src/content/docs/docs/`.
- **New pages.** A new Markdown page that belongs on the website goes in the `pages` map of `website/scripts/sync-docs.mjs` and in the `sidebar` of `website/astro.config.mjs`.
- **Landing page.** `website/src/pages/index.astro` states what works today, what doesn't yet, the measured figures and the comparison with other tools. Update it when a pull request changes any of these: a feature that ships, a roadmap change, a dependency or build change that moves the binary size, startup time or memory.
- **Base commit.** When you re-check the landing copy and figures, set `CONTENT_BASE` in `website/src/site.ts` to the commit you checked them against. Measure the figures on that commit, as the note under them describes; never carry old numbers forward under a new commit.
- **Check the build.** Run the website build when you touch docs or the website. It fails on a broken link between Markdown files.

  ```sh
  cd website && npm ci && npm run build
  ```
