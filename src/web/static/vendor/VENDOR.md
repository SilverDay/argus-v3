# Vendored front-end libraries (owner decision, Phase 9: no CDN)

Files are byte-identical copies from the npm registry tarballs. Each tarball was verified
against the registry's published `dist.integrity` (SHA-512) before extraction.

| File | Package | Version | Registry tarball | License | SHA-256 of file |
|---|---|---|---|---|---|
| htmx-2.0.11.min.js | htmx.org | 2.0.11 (dist-tag `latest`, published 2026-09-22) | https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.11.tgz (`dist/htmx.min.js`) | 0BSD (htmx-LICENSE) | d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717 |
| chart-4.5.1.umd.min.js | chart.js | 4.5.1 (dist-tag `latest`, published 2025-10-13) | https://registry.npmjs.org/chart.js/-/chart.js-4.5.1.tgz (`dist/chart.umd.min.js`) | MIT (chart.js-LICENSE.md) | 48444a82d4edcb5bec0f1965faacdde18d9c17db3063d042abada2f705c9f54a |

htmx is configured for the strict CSP (`script-src 'self'`, `style-src 'self'`) through the
`htmx-config` meta tag in `templates/base.html`: `allowEval: false`, `allowScriptTags: false`,
`includeIndicatorStyles: false`, `historyCacheSize: 0` (no page snapshots in localStorage),
`selfRequestsOnly: true`. The Chart.js file keeps its `sourceMappingURL` comment; the map is
not shipped (only requested by browser developer tools).

To update: download the new tarball, verify `dist.integrity`, copy the file, update this table.
