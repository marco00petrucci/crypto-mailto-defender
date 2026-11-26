=== Crypto Mailto Defender ===
Contributors: marco00petrucci
Tags: email, obfuscator, spam, security, mailto
Requires at least: 5.6
Tested up to: 7.0
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise spam protection. Encrypts mailto: links server-side with AES-256 and securely decrypts them via AJAX upon human interaction.

== Description ==

Tired of spam bots scraping your email addresses? Standard obfuscation techniques (like ROT13 or Base64) are easily bypassed by modern crawlers.

**Crypto Mailto Defender** uses real cryptography to protect your links.

It intercepts your HTML server-side, encrypts your `mailto:` links using an automatically generated **AES-256-CBC** key, and replaces the email with a masked version (e.g., `********@domain.com`). When a real human user clicks the link or the icon, the plugin executes a secure, nonce-protected **Server-Side AJAX request** to instantly decrypt the payload and seamlessly open their mail client. The encryption key never leaves your server.

* **Zero-Impact Performance:** JavaScript and CSS are only loaded on pages that actually contain email links.
* **Forminator Compatible:** Intercepts forms loaded via AJAX dynamically.
* **Smart UI:** Text links are revealed on the first click, while icons/buttons instantly open the mail client.

**Acknowledgements**
The idea and the study behind this plugin were inspired by the article [Email Obfuscation](https://spencermortensen.com/articles/email-obfuscation/) by Spencer Mortensen.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/crypto-mailto-defender` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. The plugin will automatically start encrypting all `mailto:` links across your site.

== Changelog ==

= 1.0.0 =
* Initial release.