# Changelog

All notable changes to **Crypto Mailto Defender** are documented in this file.

## [1.3.1]
- **Fix:** Resolved WordPress Plugin Check warnings and removed the duplicate `Tested up to` header from the main plugin file.

## [1.3.0]
- **Feature:** Added **Targeted Protection** with an interactive chip UI to protect specific emails or wildcard domains, bypassing full-site regex scanning when configured.
- **Security:** Bound AES-256-GCM AAD to `home` URL; unified anti-replay (300s TTL) and rate limiting into a 500-entry bucket with 3x failed-attempt penalty; validated parameters before touching rate-limit storage; added `Content-Type`, `Accept-Language`, and `Sec-CH-UA` checks; made secret-key init race-safe via `add_option()`.
- **Accessibility:** Added `aria-live="polite"` announcements, `aria-hidden="true"` masks with SR fallback text, `role="button"` on 2-step links, `<span>` rendering inside `<button>`, `prefers-reduced-motion`, and accessible admin controls.
- **Improvement:** Moved `mailto:` query strings into `data-cryptomail-query` so identical emails share one encrypted payload and reveal together.
- **Compatibility & Fixes:** Accepted matching `Origin`/`Referer` when `Sec-Fetch-*` headers are absent; added `mousemove`/`mousedown` fallbacks; removed invalid `noindex` from `rel`; added non-HTTPS admin notice; prevented duplicate cache purges and Forminator `preview_data` false positives; cleaned up transients on uninstall; added defensive inline CSS resets.

## [1.2.0]
- **Security:** Upgraded to **AES-256-GCM**; added multi-factor human-proof telemetry (interaction mask, DOM age, hardware score, SHA-256 PoW), anti-replay (300s TTL), object-cache rate limiting, deterministic HMAC client token (full-page cache compatible), and stricter AJAX header/UA validation.
- **Features:** Added 1-click mail client toggle, simultaneous reveal of identical emails, animated loading spinner, auto-syncing hint placeholder, and `cryptomail_skip_request`, `cryptomail_client_ip`, `cryptomail_rate_limit` filters.
- **Compatibility & Performance:** Hooked output buffering on `init` (HTML, JSON, AJAX/REST) with builder/editor detection; added 0ms early-exit, `<head>` slicing, `defer` script loading, lazy runtime init, multibyte masking, and improved `(*SKIP)(*F)` tag exclusions.
- **Changed:** Raised minimum WordPress version to **6.3**; defaulted IP detection to `REMOTE_ADDR`; removed silent clipboard copy and legacy `TreeWalker` DOM rewriting.

## [1.1.0]
- **Security:** Added hardware interaction checks (hold duration & CRC32) to block headless browsers.
- **Performance & Compatibility:** Added early-exit when `@` is absent, cache-friendly AJAX verification, and client-side in-memory caching.
- **Fix:** Resolved PHPCS warnings and updated compatibility to WordPress 7.1.

## [1.0.1]
- **Feature:** Migrated to global output buffering to cover headers, footers, and page builders.
- **Security & Performance:** Added AJAX rate limiting, safer SVG/attribute handling, and conditional asset injection.

## [1.0.0]
- Initial release.