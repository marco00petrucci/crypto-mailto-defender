=== Crypto Mailto Defender ===
Contributors: marco00petrucci
Donate link: https://www.paypal.me/marco00petrucci
Tags: email, obfuscator, spam, security, mailto
Requires at least: 5.6
Tested up to: 7.1
Stable tag: 1.1.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

🛡️ Enterprise-grade email spam protection. Encrypts mailto: links and plain emails server-side with AES-256-CBC and unlocks them only for real humans.

== Description ==

🚨 **Tired of spam bots harvesting your email addresses?** 
Standard obfuscation techniques—like ROT13, CSS direction tricks, HTML entities, or simple Base64/XOR encoding—are effortlessly bypassed in milliseconds by modern scrapers, AI crawlers, and headless browsers.

🔐 **Crypto Mailto Defender** takes a radically different approach: **real server-side cryptography**. Your email addresses never exist in the page source code or in the DOM until a verified human physically interacts with them.

### ⚡ How It Works Under the Hood
1. **Global Server-Side Interception:** The plugin captures the final HTML output before it leaves your server, finding every `mailto:` link and plain-text email across your entire layout.
2. **Military-Grade AES-256-CBC Encryption:** Every email is encrypted using a unique 256-bit secret key and a random Initialization Vector (IV), replacing the address in the HTML with a clean, customizable mask (e.g., `********@domain.com`).
3. **Hardware Human Proof Verification:** When a visitor clicks or taps an email, the plugin verifies physical interaction metrics (hold duration & CRC32 hardware signature) and performs a secure **Server-Side AJAX request** to decrypt the address on the fly. The encryption key never leaves your server.

### ✨ Key Features
* 🚀 **Ultra-Fast Early-Exit Engine:** Zero CPU wasted. If a page does not contain an `@` symbol, the regex engine is completely bypassed in 0ms—and CSS/JS assets are injected *only* on pages that actually contain emails.
* 🤖 **Anti-Headless Bot Shield:** Defeats automated scraping tools (Puppeteer, Playwright, Selenium, WebDriver, cURL, Python) by validating real hardware press timing, `isTrusted` events, and Same-Origin headers.
* ⚡ **100% Cache-Friendly:** Works seamlessly with aggressive Full-Page Caching (**Cloudflare, WP Rocket, LiteSpeed Cache, W3 Total Cache**) without breaking when WordPress nonces expire.
* 🌐 **Global Page Builder Compatibility:** Protects emails everywhere—inside standard posts, headers, footers, widgets, AJAX forms (Forminator), and builders like **Elementor, Divi, Bricks, Oxygen, and Gutenberg**.
* 📋 **Smart 2-Step UX & Auto-Copy:** Text links are revealed on the first click (and automatically copied to the user's clipboard for webmail convenience!) and open the mail client on the second click, while icon/button links launch `mailto:` immediately.
* 🛡️ **Built-In Rate Limiting:** Protects your `admin-ajax.php` endpoint against flooding attacks with Cloudflare real-IP support (`CF-Connecting-IP`).
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

= 🔍 Will masking emails hurt my website's SEO? =
Not at all. Search engines like Google do not rank pages based on plain-text email addresses, and the plugin automatically adds `rel="nofollow noindex"` to masked links to follow SEO best practices.

== Screenshots ==

1. Modern Admin Dashboard settings for Crypto Mailto Defender.

== Changelog ==

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

= 1.1.0 =
Major security & performance update: adds hardware interaction proof against headless bots (Puppeteer/Selenium), full page-caching compatibility, and 0ms early-exit optimization.