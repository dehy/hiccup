// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// The commit this build comes from, shown in the footers. GitHub Actions sets
// it; a local build has none and says so.
const commit = process.env.GITHUB_SHA ?? "";

export default defineConfig({
  site: "https://dehy.github.io",
  base: "/hiccup",
  trailingSlash: "always",
  vite: {
    define: { __BUILD_COMMIT__: JSON.stringify(commit) },
  },
  integrations: [
    starlight({
      title: "Hiccup",
      description: "A lean, open source intercepting proxy for web security testing, written in Rust.",
      favicon: "/favicon.svg",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/dehy/hiccup" }],
      customCss: ["./src/styles/fonts.css", "./src/styles/tokens.css", "./src/styles/starlight.css"],
      components: { Footer: "./src/components/DocsFooter.astro" },
      expressiveCode: {
        themes: ["github-dark-default"],
        useStarlightUiThemeColors: false,
        styleOverrides: {
          borderRadius: "12px",
          borderColor: "rgba(239, 233, 222, 0.08)",
          codeBackground: "#161513",
          codeFontFamily: '"IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace',
          codeFontSize: "14px",
          codeLineHeight: "24px",
          uiFontFamily: '"IBM Plex Sans", system-ui, sans-serif',
          frames: {
            editorActiveTabBackground: "#1c1a18",
            editorTabBarBackground: "#1c1a18",
            terminalTitlebarBackground: "#1c1a18",
            terminalBackground: "#161513",
            terminalTitlebarDotsForeground: "rgba(239, 233, 222, 0.14)",
            terminalTitlebarBorderBottomColor: "rgba(239, 233, 222, 0.08)",
            frameBoxShadowCssValue: "none",
          },
        },
      },
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Getting started", slug: "docs/getting-started" },
            { label: "Building from source", slug: "docs/building" },
            { label: "Installing the CA", slug: "docs/ca" },
            { label: "Using with AI agents", slug: "docs/ai-agents" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI", slug: "docs/cli" },
            { label: "Control API", slug: "docs/control-api" },
          ],
        },
        {
          label: "Design",
          items: [
            { label: "Architecture", slug: "docs/architecture" },
            { label: "Decision records", collapsed: true, items: [{ autogenerate: { directory: "docs/adr" } }] },
            { label: "Roadmap", slug: "docs/roadmap" },
          ],
        },
        {
          label: "Project",
          items: [
            { label: "Changelog", slug: "docs/changelog" },
            { label: "Contributing", slug: "docs/contributing" },
            { label: "Security policy", slug: "docs/security" },
            { label: "Releasing", slug: "docs/releasing" },
          ],
        },
      ],
    }),
  ],
});
