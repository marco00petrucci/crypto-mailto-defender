=== Crypto Mailto Defender ===
Contributors: marco00petrucci
Tags: email, obfuscator, spam, security, mailto
Requires at least: 5.6
Tested up to: 7.0
Stable tag: 1.0.1
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade spam protection. Encrypts mailto: links server-side using AES-256-CBC and securely decrypts them via AJAX upon human interaction.

== Description ==

Tired of spam bots scraping your email addresses? Standard obfuscation techniques (like ROT13, CSS direction tricks, or Base64) are easily bypassed by modern crawlers and scrapers.

**Crypto Mailto Defender** uses real cryptography to protect your links, ensuring absolute security without compromising user experience.

The plugin utilizes a global output buffering system to intercept your HTML server-side before it reaches the browser. It encrypts your `mailto:` links (and plain text emails) using an automatically generated **AES-256-CBC** key and replaces them with a masked version (e.g., `********@domain.com`). 

When a real human user clicks the link or the icon, the plugin executes a secure, nonce-protected **Server-Side AJAX request** to instantly decrypt the payload and seamlessly open their mail client. The encryption key never leaves your server.

### Key Features
* **Zero-Impact Performance:** JavaScript and CSS assets are dynamically injected only on pages that actually contain encrypted email links. No unnecessary code loading.
* **Global Interception:** Catches emails everywhere—inside standard content, widgets, headers, footers, and complex Page Builder layouts (Elementor, Gutenberg, Bricks, etc.).
* **Rate Limiting:** Built-in protection against AJAX flooding to prevent server abuse.
* **Strict Bot Protection:** Optionally enforce hardware-level interactions (`isTrusted` events) to block automated JS click bots like Puppeteer or Selenium.
* **Smart UI:** Text links are elegantly revealed on the first click, while icons/buttons instantly open the native mail client.
* **Forminator Compatible:** Intercepts forms loaded via AJAX dynamically.

**Acknowledgements**
The architectural idea and study behind this plugin were inspired by the article [Email Obfuscation](https://spencermortensen.com/articles/email-obfuscation/) by Spencer Mortensen.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/crypto-mailto-defender` directory, or install the plugin through the WordPress Plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. The plugin will automatically start encrypting all `mailto:` links and plain text emails across your site.
4. Navigate to **Settings > Crypto Mailto Defender** to configure masking length, hint text, and strict bot protection.

== Frequently Asked Questions ==

= Can I use this for multiple email addresses on the same page? =
Absolutely. The plugin will intercept and protect every single email address or `mailto:` link present on the page seamlessly.

= Does this plugin work with page builders like Elementor or Divi? =
Yes. Crypto Mailto Defender uses global output buffering, meaning it captures and protects emails regardless of where they are placed in the layout, including custom headers, footers, and third-party widgets.

= What happens if a user has JavaScript disabled? =
The emails will remain securely encrypted and visually masked as placeholders (e.g., `********@domain.com`). This ensures that bots mimicking non-JS environments cannot scrape the data.

= Will this affect my website's SEO? =
No. Search engine bots (like Googlebot) do not rely on reading email addresses to index or rank your pages. Masking them prevents spam scrapers from finding them while keeping your SEO entirely intact.

== Changelog ==

= 1.0.1 =
* **Feature:** Migrated to Global Output Buffering. The plugin now catches emails in headers, footers, and complex page builder layouts.
* **Security:** Added a Rate Limiting layer to the AJAX decryption endpoint to prevent server flooding attacks.
* **Fix:** Improved handling of custom SVG icons and HTML attributes, avoiding destructive sanitization when rebuilding links.
* **Performance:** Assets (CSS/JS) are now dynamically injected strictly at the end of the HTML document only when an email is actively masked.

= 1.0.0 =
* Initial release.