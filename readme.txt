=== Crypto Mailto Defender ===
Contributors: marco00petrucci
Donate link: https://www.paypal.me/marco00petrucci
Tags: email, mailto, spam, antispam, email-protection
Requires at least: 6.3
Tested up to: 7.1
Stable tag: 1.2.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

🛡️ Enterprise-grade email spam protection. Encrypts mailto: links and plain emails server-side with AES-256-GCM and unlocks them only for real humans.

== Description ==

🚨 **Tired of spam bots harvesting your email addresses?** 
Standard obfuscation techniques—like ROT13, CSS direction tricks, HTML entities, or simple Base64/XOR encoding—are effortlessly bypassed in milliseconds by modern scrapers, AI crawlers, and headless browsers.

🔐 **Crypto Mailto Defender** takes a radically different approach: **real server-side cryptography**. Your email addresses never exist in the page source code or in the DOM until a verified human physically interacts with them.

### ⚡ How It Works Under the Hood
1. **Global Server-Side Interception:** The plugin captures the final HTML output before it leaves your server, finding every `mailto:` link and plain-text email across your entire layout.
2. **Authenticated AES-256-GCM Encryption**: Every email is encrypted using a unique 256-bit secret key, a 96-bit Initialization Vector (IV), and a 128-bit authentication tag, replacing the address in the HTML with a clean, customizable mask (e.g., ********@domain.com).
3. **Hardware Human Proof & SHA-256 PoW Verification:** When a visitor clicks or taps an email, the plugin verifies physical interaction metrics (hold duration, bounding-box geometry, hardware score, and a cryptographic SHA-256 Proof-of-Work) and performs a secure **Server-Side AJAX request** to decrypt the address on the fly. The encryption key never leaves your server.

### ✨ Key Features
* 🚀 **Ultra-Fast Early-Exit Engine:** Zero CPU wasted. If a page does not contain an `@` symbol, the regex engine is completely bypassed in 0ms, and frontend JS is loaded non-blockingly via `defer`.
* 🤖 **Anti-Headless Bot Shield:** Defeats automated scraping tools (Puppeteer, Playwright, Selenium, WebDriver, cURL, Python) by validating real hardware press timing, pointer telemetry, WebGL software renderer detection, `isTrusted` events, and Same-Origin headers.
* ⚡ **100% Cache-Friendly:** Works seamlessly with aggressive Full-Page Caching (**Cloudflare, WP Rocket, LiteSpeed Cache, W3 Total Cache**) without breaking when WordPress nonces expire.
* 🌐 **Global Page Builder Compatibility:** Protects emails everywhere—inside standard posts, headers, footers, widgets, AJAX forms, and builders like **Elementor, Divi, Bricks, Oxygen, Beaver Builder, WPBakery, Breakdance, and Gutenberg**.
* 📋 **Smart 1-Step or 2-Step UX:** Choose whether text links are revealed on the first click and open the mail client on the second click, or launch `mailto:` immediately on the first click. Icon and button links always launch `mailto:` immediately.
* 🛡️ **Built-In Rate Limiting:** Protects your `admin-ajax.php` endpoint against flooding attacks using spoof-resistant IP verification (`REMOTE_ADDR`) and Object Cache support.
* ♿ **Accessible by Design:** Full keyboard navigation support (`Tab` + `Enter` / `Space`) and screen-reader friendly attributes.

### 💖 Support the Project
**Crypto Mailto Defender** is 100% free, open-source, and has no paid "Pro" upsells. If this plugin saves your inbox from spam, consider [buying me a coffee via PayPal](https://paypal.me/marco00petrucci)!

**Acknowledgements**
The architectural concept and research behind this plugin were inspired by the article [Email Obfuscation](https://spencermortensen.com/articles/email-obfuscation/) by Spencer Mortensen.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/crypto-mailto-defender` directory, or install the plugin directly through the WordPress **Plugins > Add New** screen.
2. Activate the plugin through the **Plugins** screen in WordPress.
3. Done! 🎉 The plugin immediately starts encrypting all `mailto:` links and plain-text emails across your website.
4. Go to **Settings > Crypto Mailto Defender** to customize the masking character, mask length, hint text, and strict hardware protection.

== Frequently Asked Questions ==

= 📬 Can I use this for multiple email addresses on the same page? =
Absolutely! The plugin intercepts and encrypts every single email address or `mailto:` link on the page. Plus, thanks to client-side in-memory caching, if the same email appears multiple times on a page, it only queries the server once!

= 🎨 Does this plugin work with Elementor, Divi, Bricks, or Gutenberg? =
Yes. Because Crypto Mailto Defender operates via global output buffering at the template level, it captures and protects emails regardless of how your theme or page builder renders them—including headers, footers, popups, and custom SVG icon buttons.

= ⚡ Will this plugin break with WP Rocket, Cloudflare, or LiteSpeed Cache? =
No. Version 1.1.0+ uses a cache-resilient verification mechanism that combines hardware interaction proofs with WordPress security headers, ensuring emails always unlock smoothly even on pages cached for weeks.

= 🚫 What happens if a visitor (or bot) has JavaScript disabled? =
The email addresses remain securely encrypted and visually masked (e.g., `********@domain.com`). Non-JS scrapers and raw HTML harvesters see zero email addresses in the source code.

Please note: JavaScript is required to reveal an address. Without JavaScript, nobody can reveal or use a protected email address, including legitimate visitors. If those visitors must be able to reach you, offer an alternative contact method, such as a contact form.

= 🔍 Will masking emails hurt my website's SEO? =
Not at all. Search engines like Google do not rank pages based on plain-text email addresses, and the plugin automatically adds `rel="nofollow noindex"` to masked links to follow SEO best practices.

= 🤖 Is it 100% bot-proof? =
No. It stops harvesters that read page source and common headless browsers. A determined attacker driving a real browser can still reveal an address. If an address must never be exposed, use a contact form instead.

= ☁️ Does it work behind Cloudflare or another reverse proxy? =
The rate limiter uses REMOTE_ADDR. If your server only sees the proxy's IP, restore the real visitor IP at server level or return it from the `cryptomail_client_ip` filter. The per-minute limit can be changed with the `cryptomail_rate_limit` filter.

= 🔒 Requirements? =
PHP with the OpenSSL extension, and HTTPS (the proof-of-work uses the browser's Web Crypto API, available only in secure contexts).

= ✏️ Does it affect page builders and the editor? =
Protection is skipped in the block editor, the Customizer and the preview/editing modes of common page builders. Use the `cryptomail_skip_request` filter to exclude others.

== Screenshots ==

1. Admin Dashboard settings for Crypto Mailto Defender.

== Changelog ==

= 1.2.0 =
* **Security:** Replaced AES-256-CBC with authenticated **AES-256-GCM** (12-byte IV, 16-byte tag, AAD bound to home_url) to guarantee payload integrity.
* **Security:** Introduced multi-factor **human-proof telemetry**: interaction mask (in-bounds click, pointer movement, hover/focus), DOM age, hardware score, and a SHA-256 **Proof-of-Work** challenge. Synthetic clicks and headless drivers are now reliably rejected.
* **Security:** Added **anti-replay protection** (nonce+timestamp+payload hash, 90s TTL) and upgraded rate limiting with object-cache awareness and an eviction-resistant bucket capped at 500 entries.
* **Security:** Hardened the AJAX endpoint with `Sec-Fetch-Site/Mode/Dest`, `X-Requested-With`, Origin validation, and an expanded automated-agent User-Agent blocklist.
* **Security:** Replaced expiring WordPress nonces with a deterministic **HMAC client token**, making strict-mode verification fully compatible with Cloudflare, WP Rocket, LiteSpeed, and other full-page caches.
* **Feature:** New **"Open Mail Client on First Click"** setting (1-step vs 2-step reveal UX).
* **Feature:** New **"Reveal All Identical Emails Simultaneously"** setting with in-request encryption cache to avoid duplicate AJAX calls.
* **Feature:** New **"Show Spinner Loader While Decrypting"** setting with an accessible animated loader, properly dimensioned and centered on both text links and standalone icon/button elements.
* **Feature:** Admin JS auto-syncs the hint-text placeholder when the 1-click toggle changes.
* **Feature:** Added `cryptomail_skip_request`, `cryptomail_client_ip`, and `cryptomail_rate_limit` filters for advanced integrations.
* **Compatibility:** Global output buffering now hooks `init` (priority 1) and transparently handles **HTML, JSON, and AJAX/REST fragments**, protecting emails rendered by page builders and dynamic widgets.
* **Compatibility:** Added comprehensive **builder/editor context detection** (Elementor, Divi, Bricks, Oxygen, Beaver, WPBakery, Breakdance, Brizy, Fusion, Zion, SeedProd, plus `customize_preview` and ~70 known query params) to prevent encrypting emails inside editing UIs.
* **Performance:** Ultra-fast **0ms early-exit** and `<head>` slicing before PCRE, eliminating regex scanning over styles/scripts.
* **Performance:** Modernized frontend asset delivery via `wp_enqueue_script` with the `defer` strategy instead of inline `<script>` injection.
* **Performance:** Lazy runtime initialization (`init_runtime()`), so settings and secrets are only loaded when actually needed.
* **Fix:** Multibyte-safe masking character via `mb_substr`, and unified sanitization for all settings through `sanitize_setting()`.
* **Fix:** `(*SKIP)(*F)` regex now correctly skips `head, script, style, textarea, pre, code, option, select, noscript, template, svg, iframe, object`, and HTML comments, preventing accidental masking inside non-visible contexts.
* **Changed:** Minimum WordPress version raised to **6.3**.
* **Changed:** Client-IP detection defaults to `REMOTE_ADDR` (spoof-resistant); proxy environments should use the `cryptomail_client_ip` filter.
* **Removed:** Silent clipboard copy on first reveal and the legacy `TreeWalker`/non-anchor→anchor DOM rewriting in favor of a lighter reveal path.

= 1.1.0 =
* **Security:** Introduced hardware interaction verification (hold duration & CRC32 signature) to effectively block automated headless browsers (Puppeteer, Selenium, WebDriver).
* **Performance:** Implemented ultra-fast early-exit execution if no email symbols (`@`) are present in the response HTML, dramatically reducing CPU overhead.
* **Compatibility:** Made AJAX decryption cache-friendly (WP Rocket, Cloudflare, LiteSpeed) by decoupling strict verification from expiring WordPress nonces.
* **UX:** Added client-side in-memory caching to eliminate redundant AJAX requests on duplicate emails, along with automatic clipboard copy on text links.
* **Fix:** Resolved PHPCS warnings regarding Cloudflare connecting IP sanitization and modernized tested compatibility to WordPress 7.1.

= 1.0.1 =
* **Feature:** Migrated to Global Output Buffering. The plugin now catches emails in headers, footers, and complex page builder layouts.
* **Security:** Added a Rate Limiting layer to the AJAX decryption endpoint to prevent server flooding attacks.
* **Fix:** Improved handling of custom SVG icons and HTML attributes, avoiding destructive sanitization when rebuilding links.
* **Performance:** Assets (CSS/JS) are now dynamically injected strictly at the end of the HTML document only when an email is actively masked.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.2.0 =
Security update: AES-256-GCM + SHA-256 Proof-of-Work. Payload and token format changed — purge your page cache after updating, or cached 1.1.0 pages will fail to decrypt.