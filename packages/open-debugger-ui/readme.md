# `@wae/open-debugger-ui`

WebView2 interface for OpenDebugger, implemented with [`@vmz/ui`](https://www.npmjs.com/package/@vmz/ui).

## Develop

```bash
pnpm install
pnpm --filter @wae/open-debugger-ui run check
pnpm --filter @wae/open-debugger-ui run build
pnpm --filter @wae/open-debugger-ui run stage
```

`stage` copies `dist/static` into `packages/open-debugger/dist/gui` for the native WebView2 host.

```bash
pnpm run gui
```

The page talks to the native host only through `chrome.webview` messages. Outside the host it reports that the native bridge is unavailable and shows no synthetic data.
