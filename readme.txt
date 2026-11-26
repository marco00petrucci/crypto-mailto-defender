=== Crypto Mailto Defender ===
Contributors: marco00petrucci
Donate link: https://www.paypal.me/marco00petrucci
Tags: email, mailto, spam, antispam, email-protection
Requires at least: 6.3
Tested up to: 7.1
Stable tag: 1.3.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

🛡️ Enterprise-grade email spam protection. Encrypts mailto: links and plain emails server-side with AES-256-GCM and unlocks them only for real humans.

== Description ==

Standard obfuscation tricks—ROT13, CSS direction, HTML entities, or Base64/XOR—are easily bypassed by modern scrapers, AI crawlers, and headless browsers.

🔐 **Crypto Mailto Defender** uses **real server-side cryptography**. Your email addresses never appear in the HTML source or DOM until a verified human interacts with them.

### ⚡ How It Works
1. **Global or Targeted Interception:** Captures the final output before it leaves the server, matching every `mailto:` link and plain-text email across your layout—or only the specific addresses and domains you configure.
2. **AES-256-GCM Encryption:** Encrypts each address with a unique 256-bit key, 96-bit IV, and 128-bit authentication tag, replacing it in the HTML with a customizable mask (e.g., `********@domain.com`).
3. **Human Proof & AJAX Decryption:** On click or tap, the plugin validates physical interaction metrics (press timing, geometry, hardware score, and a SHA-256 Proof-of-Work) and decrypts the address via **server-side AJAX**. The secret key never leaves your server.

### ✨ Key Features
* 🎯 **Global or Targeted Protection:** Protect all emails automatically, or restrict encryption to specific addresses (`info@example.com`) and wildcard domains (`*@example.com`), bypassing full-site regex scanning.
* 🚀 **Ultra-Fast Early-Exit Engine:** If a response has no `@` (or no configured target rule), PCRE scanning is skipped in 0ms; frontend JS loads non-blockingly via `defer`.
* 🤖 **Anti-Headless Bot Shield:** Blocks automated scrapers (Puppeteer, Playwright, Selenium, WebDriver, cURL, Python) via press timing, pointer telemetry, WebGL software-renderer checks, `isTrusted` events, and Same-Origin headers.
* ⚡ **100% Cache-Friendly:** Works with **Cloudflare, WP Rocket, LiteSpeed Cache, and W3 Total Cache** without breaking when WordPress nonces expire.
* 🌐 **Page Builder Compatible:** Protects emails in posts, headers, footers, widgets, AJAX/REST responses, and builders (**Elementor, Divi, Bricks, Oxygen, Beaver Builder, WPBakery, Breakdance, Gutenberg**).
* 📋 **1-Step or 2-Step UX:** Reveal text links on the first click and open the mail client on the second, or launch `mailto:` immediately. Icon and button links always launch immediately.
* 🛡️ **Built-In Rate Limiting:** Protects `admin-ajax.php` using `REMOTE_ADDR`, anti-replay checks, and Object Cache support.
* ♿ **Accessible by Design:** Keyboard navigation (`Tab` + `Enter` / `Space`), `aria-live` announcements, and screen-reader friendly markup.

### 💖 Support & Acknowledgements
**Crypto Mailto Defender** is 100% free and open-source, with no paid "Pro" tier. If it helps keep spam out of your inbox, consider [buying me a coffee via PayPal](https://paypal.me/marco00petrucci).

Inspired by Spencer Mortensen's article [Email Obfuscation](https://spencermortensen.com/articles/email-obfuscation/).

== Installation ==

1. Upload the plugin to `/wp-content/plugins/crypto-mailto-defender` or install it via **Plugins > Add New**.
2. Activate the plugin from the **Plugins** screen.
3. Done! All `mailto:` links and plain-text emails are protected immediately.
4. Go to **Settings > Crypto Mailto Defender** to configure targeted rules, masking style, hint text, and strict protection.

== Frequently Asked Questions ==

= 📬 Can I use this for multiple email addresses on the same page? =
Yes. Every `mailto:` link and plain-text email is protected, and client-side in-memory caching ensures identical emails on the same page—even with different `?subject=` or `?body=` parameters—query the server only once.

= 🎯 Can I protect only specific email addresses or domains? =
Yes. In **Settings > Crypto Mailto Defender**, add individual emails (`info@example.com`) or domains (`example.com` / `@example.com`). Adding at least one rule disables full-site scanning and encrypts only matching addresses.

= 🎨 Does it work with Elementor, Divi, Bricks, or Gutenberg? =
Yes. Output buffering hooks early on `init`, capturing emails across themes, page builders, headers, footers, popups, and custom SVG buttons.

= ⚡ Will it break with WP Rocket, Cloudflare, or LiteSpeed Cache? =
No. Decryption uses hardware interaction proofs, a deterministic HMAC token, and browser origin headers, so it keeps working even on pages cached for weeks.

= 🚫 What happens if JavaScript is disabled? =
Addresses remain encrypted and visually masked (e.g., `********@domain.com`), so non-JS scrapers see no emails in the HTML.

Note: JavaScript is required to reveal a protected address. If visitors without JS must be able to reach you, provide an alternative such as a contact form.

= 🔍 Will masking emails hurt SEO? =
No. Search engines do not rank pages on plain-text emails, and masked links automatically include `rel="nofollow"`.

= 🤖 Is it 100% bot-proof? =
No. It stops source-code harvesters and common headless browsers, but a determined attacker driving a real browser can still reveal an address. If an address must never be exposed, use a contact form instead.

= ☁️ Does it work behind Cloudflare or a reverse proxy? =
The rate limiter uses `REMOTE_ADDR`. If your server only sees the proxy IP, restore the real visitor IP at server level or via the `cryptomail_client_ip` filter. Adjust the per-minute limit with `cryptomail_rate_limit`.

= 🔒 Requirements? =
PHP with the OpenSSL extension, and HTTPS (the Web Crypto API used for Proof-of-Work requires a secure context).

= ✏️ Does it affect page builders or the editor? =
Protection is automatically skipped in the block editor, Customizer, and editing/preview modes of common page builders. Use `cryptomail_skip_request` to exclude others.

== Screenshots ==

1. Admin Dashboard settings for Crypto Mailto Defender.

== Changelog ==

= 1.3.0 =
* **Feature:** Added **Targeted Protection** with an interactive chip UI to protect specific emails or wildcard domains, bypassing full-site regex scanning when configured.
* **Security:** Bound AES-256-GCM AAD to `home` URL; unified anti-replay (300s TTL) and rate limiting into a 500-entry bucket with 3x failed-attempt penalty; validated parameters before touching rate-limit storage; added `Content-Type`, `Accept-Language`, and `Sec-CH-UA` checks; made secret-key init race-safe via `add_option()`.
* **Accessibility:** Added `aria-live="polite"` announcements, `aria-hidden="true"` masks with SR fallback text, `role="button"` on 2-step links, `<span>` rendering inside `<button>`, `prefers-reduced-motion`, and accessible admin controls.
* **Improvement:** Moved `mailto:` query strings into `data-cryptomail-query` so identical emails share one encrypted payload and reveal together.
* **Compatibility & Fixes:** Accepted matching `Origin`/`Referer` when `Sec-Fetch-*` headers are absent; added `mousemove`/`mousedown` fallbacks; removed invalid `noindex` from `rel`; added non-HTTPS admin notice; prevented duplicate cache purges and Forminator `preview_data` false positives; cleaned up transients on uninstall; added defensive inline CSS resets.

= 1.2.0 =
* **Security:** Upgraded to **AES-256-GCM**; added multi-factor human-proof telemetry (interaction mask, DOM age, hardware score, SHA-256 PoW), anti-replay (300s TTL), object-cache rate limiting, deterministic HMAC client token (full-page cache compatible), and stricter AJAX header/UA validation.
* **Features:** Added 1-click mail client toggle, simultaneous reveal of identical emails, animated loading spinner, auto-syncing hint placeholder, and `cryptomail_skip_request`, `cryptomail_client_ip`, `cryptomail_rate_limit` filters.
* **Compatibility & Performance:** Hooked output buffering on `init` (HTML, JSON, AJAX/REST) with builder/editor detection; added 0ms early-exit, `<head>` slicing, `defer` script loading, lazy runtime init, multibyte masking, and improved `(*SKIP)(*F)` tag exclusions.
* **Changed:** Raised minimum WordPress version to **6.3**; defaulted IP detection to `REMOTE_ADDR`; removed silent clipboard copy and legacy `TreeWalker` DOM rewriting.

= 1.1.0 =
* **Security:** Added hardware interaction checks (hold duration & CRC32) to block headless browsers.
* **Performance & Compatibility:** Added early-exit when `@` is absent, cache-friendly AJAX verification, and client-side in-memory caching.
* **Fix:** Resolved PHPCS warnings and updated compatibility to WordPress 7.1.

= 1.0.1 =
* **Feature:** Migrated to global output buffering to cover headers, footers, and page builders.
* **Security & Performance:** Added AJAX rate limiting, safer SVG/attribute handling, and conditional asset injection.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.3.0 =
Added Targeted Protection for specific emails/domains, major accessibility upgrades, and hardened AES-256-GCM AAD binding. Purge your page cache after updating from 1.2.0 so existing cached pages decrypt properly.