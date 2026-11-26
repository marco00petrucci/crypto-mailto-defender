<?php

/**
 * Plugin Name: Crypto Mailto Defender
 * Description: Enterprise spam protection. Encrypts mailto: links server-side with AES-256 and securely decrypts them via AJAX upon human interaction.
 * Version: 1.1.0
 * Author: Marco Petrucci
 * Author URI: https://linktr.ee/marco00petrucci
 * Text Domain: crypto-mailto-defender
 * Requires at least: 5.6
 * Tested up to: 7.1
 * Requires PHP: 7.4
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

namespace MarcoPetrucci\CryptoMailto;

if (!defined('ABSPATH')) {
  exit; // Exit if accessed directly
}

class Plugin
{
  private const VERSION = '1.1.0';

  private string $option_key = 'cryptomail_aes_secret';
  private string $secret;
  private string $raw_key;
  private bool $has_processed_links = false;

  // Default settings properties
  private string $mask_char = '*';
  private int $mask_length = 8;
  private string $hint_text = '(click to reveal)';
  private bool $strict_protection = true;
  private bool $obfuscate_plain = true;

  public function __construct()
  {
    $this->secret  = $this->get_secret();
    $this->raw_key = base64_decode($this->secret);
    $this->load_settings();

    // Register assets
    add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

    // Frontend filters
    add_action('template_redirect', [$this, 'start_output_buffer'], 1);

    // Secure AJAX Handlers
    add_action('wp_ajax_cryptomail_reveal', [$this, 'ajax_reveal_email']);
    add_action('wp_ajax_nopriv_cryptomail_reveal', [$this, 'ajax_reveal_email']);

    // Admin menu registration and settings initialization
    add_action('admin_menu', [$this, 'add_admin_menu']);
    add_action('admin_init', [$this, 'register_settings']);

    // Redirect to settings upon activation
    add_action('admin_init', [$this, 'redirect_after_activation']);

    // Add custom action links in the plugins page
    add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);
  }

  private function get_secret(): string
  {
    $secret = get_option($this->option_key);
    $raw    = $secret ? base64_decode($secret, true) : false;

    if ($secret === false || $raw === false || strlen($raw) !== 32) {
      $secret = base64_encode(random_bytes(32));
      update_option($this->option_key, $secret);
    }
    return $secret;
  }

  private function load_settings(): void
  {
    $this->mask_char         = get_option('cryptomail_mask_character', '*');
    $this->mask_length       = (int) get_option('cryptomail_mask_length', 8);
    $this->hint_text         = get_option('cryptomail_hint_text', '(click to reveal)');
    $this->strict_protection = (bool) get_option('cryptomail_strict_protection', 1);
    $this->obfuscate_plain   = (bool) get_option('cryptomail_obfuscate_plain', 1);
  }

  public function enqueue_admin_assets(string $hook): void
  {
    if ($hook !== 'settings_page_crypto-mailto-defender') return;
    wp_enqueue_style('cryptomail-admin-style', plugin_dir_url(__FILE__) . 'assets/css/cryptomail-admin.css', [], self::VERSION);
  }

  /** Starts catching the whole HTML output before sending it to the browser */
  public function start_output_buffer(): void
  {
    if (is_admin() || wp_doing_ajax() || wp_is_json_request() || is_feed() || (defined('REST_REQUEST') && REST_REQUEST)) {
      return;
    }
    ob_start([$this, 'process_html']);
  }

  public function process_html(string $html): string
  {
    // Ultra-fast early exit: if no '@' exists in the page, skip all regex execution
    if (empty($html) || strpos($html, '@') === false) {
      return $html;
    }

    $original_html = $html;

    // 1. Process all standard mailto: links globally
    if (stripos($html, 'mailto:') !== false) {
      $html = preg_replace_callback(
        '/<a\b([^>]*?)\shref\s*=\s*(["\'])\s*(?:mailto:\s*)+(.*?)\2([^>]*)>(.*?)<\/a>/is',
        [$this, 'replace_link'],
        $html
      );
    }

    // 2. Process plain text emails (if enabled in settings)
    if ($this->obfuscate_plain && strpos($html, '@') !== false) {
      $html = preg_replace_callback(
        '/(<a\b[^>]*>.*?<\/a>|<span\b[^>]*class=["\'][^"\']*cryptomail-plain-email[^"\']*["\'][^>]*>.*?<\/span>|<script\b[^>]*>.*?<\/script>|<style\b[^>]*>.*?<\/style>|<textarea\b[^>]*>.*?<\/textarea>|<[^>]+>)|(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)/is',
        [$this, 'replace_plain_email'],
        $html
      );
    }

    // 3. Inject CSS and JS dynamically ONLY if emails were actually encrypted on this specific page
    if ($this->has_processed_links && $html !== $original_html) {
      $html = $this->inject_assets($html);
    }

    return $html;
  }

  /**
   * Validates the email, guards against re-masking an already-masked string, and builds the masked placeholder text.
   *
   * @return array{base_masked:string,full_masked_text:string}|null
   */
  private function prepare_mask(string $email): ?array
  {
    $at = strpos($email, '@');
    if ($at === false) return null;

    $prefix = substr($email, 0, $at);
    $domain = substr($email, $at + 1);

    $char = substr($this->mask_char, 0, 1) ?: '*';

    // Prevent infinite loops/duplications if the email is already masked
    if (strspn($prefix, $char) === strlen($prefix)) return null;

    $this->has_processed_links = true;

    $length = $this->mask_length === 0 ? strlen($prefix) : $this->mask_length;
    $base_masked = str_repeat($char, $length) . '@' . $domain;
    $full_masked_text = $base_masked;

    $hint = trim($this->hint_text);
    if ($hint !== '' && strtoupper($hint) !== 'NULL') {
      $full_masked_text .= ' ' . $hint;
    }

    return [
      'base_masked'      => $base_masked,
      'full_masked_text' => $full_masked_text,
    ];
  }

  private function replace_link(array $m): string
  {
    $before_attrs = $m[1];
    $mailto_raw   = $m[3];
    $after_attrs  = $m[4];
    $inner_html   = $m[5];

    $mailto_raw = html_entity_decode($mailto_raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $mailto_raw = str_replace(["\r", "\n"], ["%0D", "%0A"], $mailto_raw);

    $segments = explode('?', $mailto_raw, 2);
    $email    = $segments[0];
    $query    = isset($segments[1]) ? $segments[1] : '';

    $mask = $this->prepare_mask($email);
    if ($mask === null) return $m[0];

    $base_masked      = $mask['base_masked'];
    $full_masked_text = $mask['full_masked_text'];

    $payload = $email . ($query !== '' ? '?' . $query : '');
    $encoded = $this->encode($payload);

    $masked_inner = str_ireplace($email, esc_html($full_masked_text), $inner_html);
    $is_text_link = ($masked_inner !== $inner_html);

    $attrs = $before_attrs . $after_attrs;

    if (stripos($attrs, $email) !== false) {
      $attrs = str_ireplace($email, esc_attr($base_masked), $attrs);
    }

    $attrs = $this->merge_attribute($attrs, 'rel', 'nofollow noindex');

    if ($is_text_link) {
      $attrs = $this->merge_attribute($attrs, 'class', 'cryptomail-text-link');
      $attrs = $this->merge_attribute($attrs, 'data-cryptomail-masked', esc_attr($full_masked_text));
    }

    return '<a' . $attrs . ' href="#" data-cryptomail-payload="' . esc_attr($encoded) . '">' . $masked_inner . '</a>';
  }

  private function replace_plain_email(array $m): string
  {
    if (!empty($m[1])) return $m[1];

    $email = $m[2];

    $mask = $this->prepare_mask($email);
    if ($mask === null) return $m[0];

    $full_masked_text = $mask['full_masked_text'];
    $encoded = $this->encode($email);

    // Use an accessible anchor link instead of a span to support keyboard navigation (Tab/Enter)
    return sprintf(
      '<a href="#" class="cryptomail-text-link cryptomail-plain-email" rel="nofollow noindex" data-cryptomail-payload="%s" data-cryptomail-masked="%s" aria-label="%s">%s</a>',
      esc_attr($encoded),
      esc_attr($full_masked_text),
      esc_attr__('Protected email address', 'crypto-mailto-defender'),
      esc_html($full_masked_text)
    );
  }

  private function merge_attribute(string $attrs, string $name, string $extra): string
  {
    $pattern = '/\s' . $name . '=(["\'])([^"\']*)\1/i';
    if (preg_match($pattern, $attrs, $rm)) {
      $values = array_unique(array_filter(array_merge(
        preg_split('/\s+/', trim($rm[2])),
        preg_split('/\s+/', $extra)
      )));
      $merged = implode(' ', $values);
      return preg_replace($pattern, ' ' . $name . '="' . $merged . '"', $attrs, 1);
    }
    return $attrs . ' ' . $name . '="' . $extra . '"';
  }

  private function encode(string $string): string
  {
    $iv = random_bytes(16);
    $ciphertext = openssl_encrypt($string, 'aes-256-cbc', $this->raw_key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ciphertext);
  }

  /** Dynamically injects CSS and JS into the footer strictly when needed */
  private function inject_assets(string $html): string
  {
    $css_url = plugin_dir_url(__FILE__) . 'assets/css/cryptomail-frontend.css';
    $js_url  = plugin_dir_url(__FILE__) . 'assets/js/cryptomail-frontend.js';

    $ajax_url = admin_url('admin-ajax.php');
    $nonce    = wp_create_nonce('cryptomail_reveal_nonce');
    $strict   = $this->strict_protection ? '1' : '0';
    $error    = esc_html__('Decryption failed. Request blocked.', 'crypto-mailto-defender');

    $config = wp_json_encode([
      'ajaxUrl'    => $ajax_url,
      'nonce'      => $nonce,
      'strictMode' => $strict,
      'errorMsg'   => $error
    ]);

    $inject = "\n<!-- Crypto Mailto Defender Assets -->\n";
    // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet
    $inject .= "<link rel='stylesheet' id='cryptomail-frontend-css' href='" . esc_url($css_url . '?ver=' . self::VERSION) . "' media='all' />\n";
    $inject .= "<script id='cryptomail-frontend-js-extra'>\nvar cryptomailConfig = " . $config . ";\n</script>\n";
    // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
    $inject .= "<script src='" . esc_url($js_url . '?ver=' . self::VERSION) . "' id='cryptomail-frontend-js'></script>\n";

    if (stripos($html, '</body>') !== false) {
      return str_ireplace('</body>', $inject . '</body>', $html);
    }

    return $html . $inject;
  }

  /** AJAX endpoint for secure decryption with Rate Limiting & Anti-Bot checks */
  public function ajax_reveal_email(): void
  {
    // 1. Verify Origin / XHR headers (or fallback to standard WordPress nonce)
    $sec_fetch_site = isset($_SERVER['HTTP_SEC_FETCH_SITE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_FETCH_SITE'])) : '';
    if ($sec_fetch_site !== '' && !in_array($sec_fetch_site, ['same-origin', 'same-site', 'none'], true)) {
      wp_send_json_error(['message' => esc_html__('Unauthorized request origin.', 'crypto-mailto-defender')]);
    }

    // 2. Block User-Agent for known scrapers, crawlers, and headless bots
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
    if ($ua === '' || preg_match('/bot|crawl|spider|curl|wget|python|scrapy|headless/i', $ua)) {
      wp_send_json_error(['message' => esc_html__('Automated access denied.', 'crypto-mailto-defender')]);
    }

    // 3. Retrieve real client IP supporting Cloudflare proxy headers with strict sanitization
    $ip = 'unknown';
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
      $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
    } elseif (isset($_SERVER['REMOTE_ADDR'])) {
      $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
    }

    $transient_key = 'cryptomail_rate_' . md5($ip);
    $attempts = (int) get_transient($transient_key);

    if ($attempts >= 30) {
      wp_send_json_error(['message' => esc_html__('Too many requests. Please slow down.', 'crypto-mailto-defender')]);
    }
    set_transient($transient_key, $attempts + 1, MINUTE_IN_SECONDS);

    // 4. Payload & Human Proof / Nonce verification
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $payload = isset($_POST['payload']) ? sanitize_text_field(wp_unslash($_POST['payload'])) : '';
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $proof   = isset($_POST['proof']) ? sanitize_text_field(wp_unslash($_POST['proof'])) : '';
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $nonce   = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';

    if (empty($payload)) {
      wp_send_json_error(['message' => esc_html__('No payload provided.', 'crypto-mailto-defender')]);
    }

    // Accept the request if the hardware human proof is valid OR if the WP nonce is valid (when not in Strict Mode)
    $proof_valid = $this->verify_human_proof($payload, $proof);
    $nonce_valid = !empty($nonce) && wp_verify_nonce($nonce, 'cryptomail_reveal_nonce');

    if ($this->strict_protection) {
      if (!$proof_valid && !$nonce_valid) {
        wp_send_json_error(['message' => esc_html__('Bot protection triggered.', 'crypto-mailto-defender')]);
      }
    }

    $data = base64_decode($payload, true);
    if ($data === false || strlen($data) <= 16) {
      wp_send_json_error(['message' => esc_html__('Invalid payload format.', 'crypto-mailto-defender')]);
    }

    $iv = substr($data, 0, 16);
    $ciphertext = substr($data, 16);

    // AES decryption
    $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $this->raw_key, OPENSSL_RAW_DATA, $iv);

    if ($decrypted !== false) {
      wp_send_json_success(['email' => $decrypted]);
    } else {
      wp_send_json_error(['message' => esc_html__('Decryption failed. Integrity check error.', 'crypto-mailto-defender')]);
    }
  }

  private function verify_human_proof(string $payload, string $proof): bool
  {
    if ($proof === '') return false;

    $decoded = base64_decode($proof, true);
    if ($decoded === false) return false;

    $parts = explode('|', $decoded);
    if (count($parts) !== 3) return false;

    [$ts, $hold_ms, $sig] = $parts;
    if (!ctype_digit($ts) || !ctype_digit($hold_ms)) return false;

    // On mobile/touchpad a human tap lasts at least 1ms; synthetic JS clicks take 0ms
    if ((int) $hold_ms < 1 || (int) $hold_ms > 30000) return false;

    $expected = substr($payload, 0, 16) . ':' . $ts . ':' . $hold_ms;
    // sprintf('%u') forces an unsigned 32-bit integer matching JavaScript's (>>> 0)
    $expected_sig = sprintf('%u', crc32($expected));

    return hash_equals($expected_sig, $sig);
  }

  // =========================================================================
  // ADMIN DASHBOARD
  // =========================================================================

  public function add_admin_menu(): void
  {
    add_options_page(
      __('Crypto Mailto Defender', 'crypto-mailto-defender'),
      __('Crypto Mailto Defender', 'crypto-mailto-defender'),
      'manage_options',
      'crypto-mailto-defender',
      [$this, 'render_admin_page']
    );
  }

  public function register_settings(): void
  {
    register_setting('cryptomail_settings_group', 'cryptomail_strict_protection', 'absint');
    register_setting('cryptomail_settings_group', 'cryptomail_obfuscate_plain', 'absint');
    register_setting('cryptomail_settings_group', 'cryptomail_mask_character', 'sanitize_text_field');
    register_setting('cryptomail_settings_group', 'cryptomail_mask_length', 'absint');
    register_setting('cryptomail_settings_group', 'cryptomail_hint_text', 'sanitize_text_field');

    add_settings_section('cryptomail_main_section', '', '__return_false', 'crypto-mailto-defender');

    add_settings_field('cryptomail_strict_protection', __('Strict Bot Protection', 'crypto-mailto-defender'), [$this, 'render_strict_field'], 'crypto-mailto-defender', 'cryptomail_main_section');
    add_settings_field('cryptomail_obfuscate_plain', __('Protect Unlinked Emails', 'crypto-mailto-defender'), [$this, 'render_plain_email_field'], 'crypto-mailto-defender', 'cryptomail_main_section');
    add_settings_field('cryptomail_masking_group', __('Visual Masking', 'crypto-mailto-defender'), [$this, 'render_masking_fields'], 'crypto-mailto-defender', 'cryptomail_main_section');
    add_settings_field('cryptomail_hint_text', __('Hint Text', 'crypto-mailto-defender'), [$this, 'render_hint_field'], 'crypto-mailto-defender', 'cryptomail_main_section');
  }

  /** Shared markup renderer for the toggle-switch settings fields. */
  private function render_switch_field(string $option_name, int $default, string $label, string $description): void
  {
    $value = get_option($option_name, $default);
?>
    <div class="cryptomail-switch-row">
      <label class="cryptomail-switch">
        <input type="hidden" name="<?php echo esc_attr($option_name); ?>" value="0">
        <input type="checkbox" name="<?php echo esc_attr($option_name); ?>" value="1" <?php checked(1, $value, true); ?>>
        <span class="cryptomail-slider"></span>
      </label>
      <div class="cryptomail-switch-text">
        <strong><?php echo esc_html($label); ?></strong>
      </div>
    </div>
    <p class="description">
      <?php echo esc_html($description); ?>
    </p>
  <?php
  }

  public function render_strict_field(): void
  {
    $this->render_switch_field(
      'cryptomail_strict_protection',
      1,
      __('Hardware Interaction Required', 'crypto-mailto-defender'),
      __('When enabled, decryption triggers ONLY upon a verified physical interaction (measuring press duration and blocking automated browser drivers). This prevents headless bots like Puppeteer or Selenium from scraping addresses.', 'crypto-mailto-defender')
    );
  }

  public function render_plain_email_field(): void
  {
    $this->render_switch_field(
      'cryptomail_obfuscate_plain',
      1,
      __('Protect Unlinked Emails', 'crypto-mailto-defender'),
      __('Automatically finds and protects emails that are just written in text, without a mailto: link. Once revealed by the user, they will automatically become clickable mail links.', 'crypto-mailto-defender')
    );
  }

  public function render_masking_fields(): void
  {
    $char_value = get_option('cryptomail_mask_character', '*');
    $len_value  = get_option('cryptomail_mask_length', 8);
  ?>
    <div style="display:flex; gap:20px; flex-wrap:wrap;">
      <div>
        <strong><?php esc_html_e('Masking Character', 'crypto-mailto-defender'); ?></strong><br>
        <input type="text" name="cryptomail_mask_character" value="<?php echo esc_attr($char_value); ?>" maxlength="1" class="cryptomail-input-small" style="margin-top: 8px;">
        <p class="description"><?php esc_html_e('Character used to hide the email (e.g. *, •, -).', 'crypto-mailto-defender'); ?></p>
      </div>
      <div>
        <strong><?php esc_html_e('Mask Length', 'crypto-mailto-defender'); ?></strong><br>
        <input type="number" name="cryptomail_mask_length" value="<?php echo esc_attr($len_value); ?>" min="0" max="50" class="cryptomail-input-small" style="margin-top: 8px;">
        <p class="description"><?php esc_html_e('Fixed number of characters. Set to 0 to match the exact length of the real email prefix.', 'crypto-mailto-defender'); ?></p>
      </div>
    </div>
  <?php
  }

  public function render_hint_field(): void
  {
    $value = get_option('cryptomail_hint_text', '(click to reveal)');
  ?>
    <input type="text" name="cryptomail_hint_text" value="<?php echo esc_attr($value); ?>" placeholder="(click to reveal)">
    <p class="description">
      <?php esc_html_e('Text displayed next to the obfuscated email address on the frontend. Leave empty or type "NULL" to display nothing.', 'crypto-mailto-defender'); ?>
    </p>
  <?php
  }

  public function render_admin_page(): void
  {
    if (!current_user_can('manage_options')) return;
  ?>
    <div class="wrap cryptomail-dashboard-wrap">
      <h1 class="wp-heading-inline" style="display:none;">Crypto Mailto Defender</h1>

      <div class="cryptomail-bg-shape cryptomail-shape-1"></div>
      <div class="cryptomail-bg-shape cryptomail-shape-2"></div>

      <div class="cryptomail-header">
        <div class="cryptomail-brand">
          <div class="cryptomail-logo-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M16 10H8C6.89543 10 6 10.8954 6 12V16C6 17.1046 6.89543 18 8 18H16C17.1046 18 18 17.1046 18 16V12C18 10.8954 17.1046 10 16 10Z" fill="white" />
              <path d="M12 10V7C12 5.34315 10.6569 4 9 4C7.34315 4 6 5.34315 6 7" stroke="white" stroke-width="2" stroke-linecap="round" />
            </svg>
          </div>
          <div>
            <h2 class="cryptomail-title"><?php esc_html_e('Crypto Mailto Defender', 'crypto-mailto-defender'); ?></h2>
            <p><?php esc_html_e('Manage and configure the AES-256 encrypted email protection for your users.', 'crypto-mailto-defender'); ?></p>
          </div>
        </div>
        <div class="cryptomail-version-badge">v<?php echo esc_html(self::VERSION); ?></div>
      </div>

      <div class="cryptomail-grid-layout">
        <div class="cryptomail-main-col">
          <form method="post" action="options.php">
            <?php
            settings_fields('cryptomail_settings_group');
            do_settings_sections('crypto-mailto-defender');
            ?>
            <div class="cryptomail-floating-bar">
              <div class="cryptomail-bar-content">
                <div class="cryptomail-bar-text">
                  <strong><?php esc_html_e('Did you make changes?', 'crypto-mailto-defender'); ?></strong>
                  <span><?php esc_html_e('Remember to save to apply them to the site.', 'crypto-mailto-defender'); ?></span>
                </div>
                <button type="submit" class="cryptomail-btn-primary">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M19 21H5C3.89543 21 3 20.1046 3 19V5C3 3.89543 3.89543 3 5 3H16L21 8V19C21 20.1046 20.1046 21 19 21Z" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M17 21V13H7V21" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M7 3V8H15V3" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  <?php esc_html_e('Save Configuration', 'crypto-mailto-defender'); ?>
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
<?php
  }

  /** Set a flag in the database upon plugin activation. */
  public static function activate(): void
  {
    add_option('cryptomail_activation_redirect', true);
  }

  /** Redirect the user to the settings page after plugin activation. */
  public function redirect_after_activation(): void
  {
    if (get_option('cryptomail_activation_redirect', false)) {
      delete_option('cryptomail_activation_redirect');

      // phpcs:ignore WordPress.Security.NonceVerification.Recommended
      if (!isset($_GET['activate-multi'])) {
        wp_safe_redirect(admin_url('options-general.php?page=crypto-mailto-defender'));
        exit;
      }
    }
  }

  public function add_settings_link(array $links): array
  {
    $settings_url = admin_url('options-general.php?page=crypto-mailto-defender');
    $settings_link = '<a href="' . esc_url($settings_url) . '">' . esc_html__('Settings', 'crypto-mailto-defender') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
  }

  /** Clean up all plugin options upon uninstallation. */
  public static function uninstall(): void
  {
    $options = [
      'cryptomail_aes_secret',
      'cryptomail_mask_character',
      'cryptomail_mask_length',
      'cryptomail_hint_text',
      'cryptomail_strict_protection',
      'cryptomail_obfuscate_plain',
      'cryptomail_activation_redirect',
    ];
    foreach ($options as $opt) {
      delete_option($opt);
    }
  }
}

register_activation_hook(__FILE__, ['MarcoPetrucci\CryptoMailto\Plugin', 'activate']);
register_uninstall_hook(__FILE__, ['MarcoPetrucci\CryptoMailto\Plugin', 'uninstall']);

new Plugin();
