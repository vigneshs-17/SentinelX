# Vendored test dependency: axe-core

- `axe.min.js`: axe-core 4.14.0, from the npm registry tarball <https://registry.npmjs.org/axe-core/-/axe-core-4.14.0.tgz>
  (tarball SHA-1 a9819d3932a8198fbe935d8cbd8afcdfecbcf31d, as published by the registry).
- SHA-256 of `axe.min.js`: `20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878`.
- `axe-core.LICENSE`: the MPL-2.0 licence text shipped in the package.

It is used only by the browser tests, loaded from this local file (never from a CDN) and evaluated in the page through the
DevTools protocol, so the app's strict Content-Security-Policy stays untouched. It is not served by the application.
