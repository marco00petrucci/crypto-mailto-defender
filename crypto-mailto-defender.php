<?php

/**
 * Plugin Name: Crypto Mailto Defender
 * Description: Enterprise spam protection. Encrypts mailto: links server-side with AES-256 and securely decrypts them via AJAX upon human interaction.
 * Version: 1.2.0
 * Author: Marco Petrucci
 * Author URI: https://linktr.ee/marco00petrucci
 * Text Domain: crypto-mailto-defender
 * Requires at least: 6.3
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
  private const VERSION = '1.2.0';
  private const CIPHER_AAD = 'cryptomail_v1';

  private const SECRET_OPTION = 'cryptomail_aes_secret';
  private string $raw_key;

  /** @var array<string, string> In-memory cache to avoid duplicate encryption within the same request */
  private array $encoded_cache = [];

  /** Settings: option name = 'cryptomail_' . key. Property names must match the keys. */
  private const DEFAULTS = [
    'strict_protection'   => 1,
    'obfuscate_plain'     => 1,
    'open_on_first_click' => 0,
    'reveal_all_matching' => 1,
    'show_loader'         => 1,
    'mask_character'      => '*',
    'mask_length'         => 8,
    'hint_text'           => '(click to reveal)',
  ];

  private string $mask_character = '*';
  private int $mask_length = 8;
  private string $hint_text = '';
  private bool $strict_protection = true;
  private bool $obfuscate_plain = true;
  private bool $open_on_first_click = false;
  private bool $reveal_all_matching = true;
  private bool $show_loader = true;
  private bool $buffer_started = false;
  private bool $initialized = false;
  private ?bool $skip_cache = null;

  private const BUILDER_PARAMS = ['elementor-preview', 'elementor_library', 'et_fb', 'et_vb', 'et_pb_preview', 'et_bfb', 'bricks', 'brickspreview', 'fl_builder', 'fl_builder_preview', 'ct_builder', 'ct_inner', 'oxygen', 'oxygen_iframe', 'vc_editable', 'vc_action', 'vcv-action', 'vcv-editable', 'brizy-edit', 'brizy-edit-iframe', 'is-editor-iframe', 'fb-edit', 'fusion_load_nonce', 'builder', 'breakdance', 'breakdance_iframe', 'cs_preview_state', 'cornerstone_preview', 'cs-render', 'tve', 'tar_editor_page', 'zionbuilder-preview', 'zionbuilder-barebone-preview', 'seedprod_builder', 'dslc', 'so_live_editor', 'siteorigin_panels_live_editor', 'td_action', 'lc_action_launch_editing', 'lc_page_editing_mode', 'pagelayer-live', 'kubio-preview', 'colibri-preview', 'mpce-edit', 'op3-editor', 'fse-preview', 'wp-find-template', 'legacy-widget-preview', 'wp_scrape_key', 'gutenberg-frame', 'customize_changeset_uuid', 'wp_customize', 'uxb_iframe'];

  private function get_client_token(): string
  {
    return substr(hash_hmac('sha256', self::CIPHER_AAD . '|' . home_url(), $this->raw_key), 0, 32);
  }

  private function get_pow_diff(): int
  {
    return $this->strict_protection ? 15 : 10;
  }

  public function __construct()
  {
    // Register admin & frontend assets
    add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
    add_action('wp_enqueue_scripts', [$this, 'enqueue_frontend_assets']);

    // Universal entry point (covers frontend HTML, shortcodes, widgets, AJAX fragments, and REST JSON)
    add_action('init', [$this, 'start_output_buffer'], 1);

    // Secure AJAX Handlers
    add_action('wp_ajax_cryptomail_reveal', [$this, 'ajax_reveal_email']);
    add_action('wp_ajax_nopriv_cryptomail_reveal', [$this, 'ajax_reveal_email']);

    // Admin menu registration, settings initialization and admin notices
    add_action('admin_menu', [$this, 'add_admin_menu']);
    add_action('admin_init', [$this, 'register_settings']);
    add_action('admin_notices', [$this, 'admin_notices']);

    // Purge page caches when plugin settings are updated
    foreach (array_keys(self::DEFAULTS) as $opt_key) {
      add_action('update_option_cryptomail_' . $opt_key, [$this, 'purge_page_caches'], 10, 0);
    }

    // Redirect to settings upon activation
    add_action('admin_init', [$this, 'redirect_after_activation']);

    // Add custom action links in the plugins page
    add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);
  }

  private function get_secret(): string
  {
    $secret = get_option(self::SECRET_OPTION);
    $raw = is_string($secret) ? base64_decode($secret, true) : false;

    if ($raw === false || strlen($raw) !== 32) {
      $secret = base64_encode(random_bytes(32));
      update_option(self::SECRET_OPTION, $secret, true);
    }
    return $secret;
  }

  private function init_runtime(): void
  {
    if ($this->initialized) {
      return;
    }
    $this->raw_key = (string) base64_decode($this->get_secret(), true);
    foreach (self::DEFAULTS as $key => $default) {
      $val = get_option('cryptomail_' . $key, $default);
      $this->$key = is_int($default) ? ($key === 'mask_length' ? (int) $val : (bool) $val) : (string) $val;
    }
    $this->hint_text   = $this->resolve_hint($this->hint_text);
    $this->initialized = true;
  }

  private function resolve_hint(string $saved): string
  {
    $plain = __('(click to reveal)', 'crypto-mailto-defender');
    $send  = __('(click to reveal and send)', 'crypto-mailto-defender');
    if (in_array($saved, ['(click to reveal)', '(click to reveal and send)', $plain, $send], true)) {
      return $this->open_on_first_click ? $send : $plain;
    }
    return $saved;
  }

  public function enqueue_admin_assets(string $hook): void
  {
    if ($hook !== 'settings_page_crypto-mailto-defender') {
      return;
    }

    wp_enqueue_style(
      'cryptomail-admin-style',
      plugin_dir_url(__FILE__) . 'assets/css/cryptomail-admin.css',
      [],
      self::VERSION
    );

    wp_enqueue_script(
      'cryptomail-admin-script',
      plugin_dir_url(__FILE__) . 'assets/js/cryptomail-admin.js',
      [],
      self::VERSION,
      true
    );

    wp_localize_script('cryptomail-admin-script', 'cryptomailAdminL10n', [
      'defaultHint'       => __('(click to reveal)', 'crypto-mailto-defender'),
      'defaultHintAction' => __('(click to reveal and send)', 'crypto-mailto-defender'),
    ]);
  }

  public function enqueue_frontend_assets(): void
  {
    if ($this->is_builder_or_editor_context()) {
      return;
    }

    if (function_exists('current_user_can') && current_user_can('edit_posts')) {
      delete_transient('cryptomail_ed_' . get_current_user_id());
    }

    $this->init_runtime();

    wp_enqueue_style(
      'cryptomail-frontend-css',
      plugin_dir_url(__FILE__) . 'assets/css/cryptomail-frontend.css',
      [],
      self::VERSION
    );

    wp_enqueue_script(
      'cryptomail-frontend-js',
      plugin_dir_url(__FILE__) . 'assets/js/cryptomail-frontend.js',
      [],
      self::VERSION,
      [
        'in_footer' => true,
        'strategy'  => 'defer',
      ]
    );

    wp_localize_script('cryptomail-frontend-js', 'cryptomailConfig', [
      'ajaxUrl'          => admin_url('admin-ajax.php'),
      'token'            => $this->get_client_token(),
      'powDiff'          => (string) $this->get_pow_diff(),
      'strictMode'       => $this->strict_protection ? '1' : '0',
      'openOnFirstClick' => $this->open_on_first_click ? '1' : '0',
      'revealAll'        => $this->reveal_all_matching ? '1' : '0',
      'showLoader'       => $this->show_loader ? '1' : '0',
      'errorMsg'         => esc_html__('Decryption failed. Request blocked.', 'crypto-mailto-defender'),
    ]);
  }

  /**
   * Detects if the current request is inside an editor, customizer, or page builder context to prevent encrypting emails inside editor forms or saving masked HTML into the database.
   */
  private function is_builder_or_editor_context(): bool
  {
    if ($this->skip_cache !== null) {
      return $this->skip_cache;
    }

    $can_edit = function_exists('current_user_can') && current_user_can('edit_posts');
    $user_id  = $can_edit ? get_current_user_id() : 0;

    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    $uri     = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
    $rest_p  = '/' . rest_get_url_prefix() . '/';
    $is_rest = (defined('REST_REQUEST') && REST_REQUEST)
      || isset($_REQUEST['rest_route'])
      || ($uri !== '' && strpos($uri, $rest_p) !== false);

    $action_regex = '/^(?:edit|elementor|bricks|fl_builder|ct_|et_|vc_|vcv|brizy|architect|tve|kubio|pagelayer|fusion|breakdance|zion)/i';
    $context      = isset($_REQUEST['context']) ? sanitize_key(wp_unslash($_REQUEST['context'])) : '';
    $action       = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
    $is_preview   = (function_exists('is_preview') && is_preview())
      || (isset($_REQUEST['is_preview']) && filter_var(wp_unslash($_REQUEST['is_preview']), FILTER_VALIDATE_BOOLEAN))
      || (isset($_REQUEST['preview']) && filter_var(wp_unslash($_REQUEST['preview']), FILTER_VALIDATE_BOOLEAN))
      || !empty($_REQUEST['preview_data']);

    $skip = (is_admin() && !wp_doing_ajax())
      || is_customize_preview()
      || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
      || $context === 'edit'
      || ($can_edit && ($is_rest || $is_preview || preg_match($action_regex, $action)))
      || did_action('elementor/editor/before_enqueue_scripts')
      || did_action('cs_before_preview_frame')
      || (function_exists('\bricks_is_builder') && \bricks_is_builder())
      || (function_exists('\bricks_is_builder_call') && \bricks_is_builder_call())
      || (function_exists('\et_core_is_fb_enabled') && \et_core_is_fb_enabled())
      || (class_exists('\FLBuilderModel') && method_exists('\FLBuilderModel', 'is_builder_active') && \FLBuilderModel::is_builder_active())
      || (function_exists('\vc_is_page_editable') && \vc_is_page_editable())
      || (function_exists('\vc_is_inline') && \vc_is_inline())
      || (function_exists('\fusion_is_preview_frame') && \fusion_is_preview_frame())
      || (function_exists('\fusion_is_builder_frame') && \fusion_is_builder_frame())
      || (function_exists('\Breakdance\isRequestFromBuilderIframe') && \Breakdance\isRequestFromBuilderIframe());

    if (!$skip) {
      $query_keys = array_map('sanitize_key', array_keys(wp_unslash($_REQUEST)));
      $sec_dest   = isset($_SERVER['HTTP_SEC_FETCH_DEST']) ? sanitize_key(wp_unslash($_SERVER['HTTP_SEC_FETCH_DEST'])) : '';
      $referers   = array_filter([
        'http'       => isset($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : '',
        'wp'         => isset($_REQUEST['_wp_http_referer']) ? sanitize_text_field(wp_unslash($_REQUEST['_wp_http_referer'])) : '',
        'extra_wp'   => isset($_REQUEST['extra']['_wp_http_referer']) ? sanitize_text_field(wp_unslash($_REQUEST['extra']['_wp_http_referer'])) : '',
        'extra_url'  => isset($_REQUEST['extra']['referer_url']) ? sanitize_text_field(wp_unslash($_REQUEST['extra']['referer_url'])) : '',
        'direct_url' => isset($_REQUEST['referer_url']) ? sanitize_text_field(wp_unslash($_REQUEST['referer_url'])) : '',
      ]);
      // phpcs:enable

      if (wp_doing_ajax() || $is_rest || isset($_SERVER['HTTP_X_WP_NONCE']) || ($can_edit && $sec_dest !== 'document')) {
        $admin_path = (string) wp_parse_url(admin_url(), PHP_URL_PATH);
        foreach ($referers as $source => $referer) {
          $ref_path = (string) wp_parse_url($referer, PHP_URL_PATH);
          if (
            ($admin_path !== '' && strpos($ref_path, $admin_path) === 0 && ($source !== 'http' || strpos($ref_path, 'admin-ajax.php') === false)) ||
            ($can_edit && $ref_path !== '' && strpos($ref_path, $rest_p) !== false)
          ) {
            $skip = true;
            break;
          }
          $from_referer = [];
          wp_parse_str((string) wp_parse_url($referer, PHP_URL_QUERY), $from_referer);
          $ref_context = isset($from_referer['context']) ? sanitize_key($from_referer['context']) : '';
          $ref_action  = isset($from_referer['action']) ? sanitize_key($from_referer['action']) : '';
          $ref_preview = !empty($from_referer['preview']) || !empty($from_referer['is_preview']) || !empty($from_referer['preview_id']);
          if ($ref_context === 'edit' || ($can_edit && ($ref_preview || preg_match($action_regex, $ref_action)))) {
            $skip = true;
            break;
          }
          if (!empty($from_referer)) {
            $query_keys = array_merge($query_keys, array_map('sanitize_key', array_keys($from_referer)));
          }
        }
      }

      if (!$skip) {
        $skip = !empty(array_intersect(self::BUILDER_PARAMS, $query_keys))
          || ($can_edit && wp_doing_ajax() && (bool) get_transient('cryptomail_ed_' . $user_id));
      }
    }

    $result = (bool) apply_filters('cryptomail_skip_request', $skip);

    if ($result && $user_id > 0 && !get_transient('cryptomail_ed_' . $user_id)) {
      set_transient('cryptomail_ed_' . $user_id, 1, 600);
    }

    if ($result || did_action('wp') > 0 || wp_doing_ajax()) {
      $this->skip_cache = $result;
    }

    return $result;
  }

  /** Starts capturing output across standard frontend pages as well as frontend AJAX/REST requests */
  public function start_output_buffer(): void
  {
    if ($this->buffer_started) {
      return;
    }

    if ((defined('DOING_CRON') && constant('DOING_CRON')) || (defined('WP_CLI') && constant('WP_CLI'))) {
      return;
    }

    if ($this->is_builder_or_editor_context()) {
      return;
    }

    if (wp_doing_ajax()) {
      // phpcs:ignore WordPress.Security.NonceVerification.Recommended
      $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
      if ($action === '' || $action === 'cryptomail_reveal' || preg_match('/(?:heartbeat|save|edit|admin|elementor|bricks|divi|builder|oxy|vc_|update|delete|install|query-attachments|oembed)/i', $action)) {
        return;
      }
    }

    $this->buffer_started = true;
    ob_start([$this, 'process_buffer']);
  }

  /** Universal buffer router: automatically distinguishes between full HTML documents, AJAX HTML fragments, and JSON payloads */
  public function process_buffer(string $buffer): string
  {
    // 0ms C-level early exit before invoking PCRE engine
    if ($buffer === '' || (strpos($buffer, '@') === false && strpos($buffer, '\u0040') === false)) {
      return $buffer;
    }

    if (!preg_match('/[\w.+-]@[\w-]+\.[a-z]/i', $buffer) && strpos($buffer, '\u0040') === false) {
      return $buffer;
    }

    if ($this->is_builder_or_editor_context() || is_feed() || is_robots() || is_trackback()) {
      return $buffer;
    }

    foreach (headers_list() as $header) {
      if (stripos($header, 'content-type:') === 0 && !preg_match('#text/html|json|text/plain#i', $header)) {
        return $buffer;
      }
    }

    $this->init_runtime();

    // JSON payloads (AJAX forms, REST, WooCommerce fragments)
    $first_char = $buffer[strspn($buffer, " \t\n\r")] ?? '';
    if ($first_char === '{' || $first_char === '[') {
      $decoded = json_decode($buffer, false);
      if (json_last_error() === JSON_ERROR_NONE && (is_array($decoded) || is_object($decoded))) {
        $modified = false;
        $data     = $this->process_json_recursive($decoded, $modified);
        return $modified ? (wp_json_encode($data) ?: $buffer) : $buffer;
      }
    }

    return $this->process_html_fragment($buffer);
  }

  /**
   * Recursively traverses any JSON structure and obfuscates only strings containing HTML or emails.
   *
   * @param mixed $data
   * @return mixed
   */
  private function process_json_recursive($data, bool &$modified)
  {
    if (is_array($data) || is_object($data)) {
      foreach ($data as $key => $value) {
        // Skip technical keys that are not meant for HTML rendering
        if (is_string($key) && in_array($key, ['id', 'slug', 'redirect', 'url', 'nonce', '_wpnonce', 'action', 'status', 'type', 'settings', 'editLink'], true)) {
          continue;
        }
        $new = $this->process_json_recursive($value, $modified);
        if (is_object($data)) {
          $data->{$key} = $new;
        } else {
          $data[$key] = $new;
        }
      }
      return $data;
    }

    if (is_string($data) && strpos($data, '@') !== false && (strpos($data, '<') !== false || stripos($data, 'mailto:') !== false)) {
      $new_data = $this->process_html_fragment($data);
      if ($new_data !== $data) {
        $modified = true;
        return $new_data;
      }
    }

    return $data;
  }

  public function process_html_fragment(string $html): string
  {
    if ($html === '' || strpos($html, '@') === false) {
      return $html;
    }

    // Slice off <head>...</head> in 0ms to avoid PCRE scanning/backtracking over head styles & scripts
    $head_prefix = '';
    $body_pos    = stripos($html, '<body');
    if ($body_pos !== false) {
      $head_prefix = substr($html, 0, $body_pos);
      $html        = substr($html, $body_pos);
      if (strpos($html, '@') === false) {
        return $head_prefix . $html;
      }
    }

    // 1. Process all mailto: links
    if (stripos($html, 'mailto:') !== false) {
      $html = preg_replace_callback(
        '/(?:<(script|style|textarea|pre|code|template)\b[^>]*+>.*?<\/\1>|<!--.*?-->)(*SKIP)(*F)|<a\b([^>]*?)\shref\s*=\s*(["\'])\s*(?:mailto:\s*)+((?:(?!\3).)+?)\3([^>]*)>(.*?)<\/a>/isS',
        [$this, 'replace_link'],
        $html
      ) ?? $html;
    }

    // 2. Process plain text emails (button removed from skip list so emails inside <button> are protected)
    if ($this->obfuscate_plain && strpos($html, '@') !== false) {
      $html = preg_replace_callback(
        '/(?:<(head|a|script|style|textarea|pre|code|option|select|noscript|template|svg|iframe|object)\b[^>]*+>.*?<\/\1>|<!--.*?-->|<[^>]*+>)(*SKIP)(*F)|\b([A-Za-z0-9._%+-]++@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b/isS',
        [$this, 'replace_plain_email'],
        $html
      ) ?? $html;
    }

    return $head_prefix . $html;
  }

  /**
   * Validates the email, guards against asset filenames or re-masking, and builds the masked placeholder markup.
   *
   * @return array{base_masked:string,masked_html:string}|null
   */
  private function prepare_mask(string $email): ?array
  {
    $at = strpos($email, '@');
    if ($at === false || !is_email($email)) {
      return null;
    }

    $prefix = substr($email, 0, $at);
    $domain = substr($email, $at + 1);

    // Ignore retina assets and package identifiers (e.g. image@2x.png, script@1.2.js)
    if (preg_match('/\.(?:png|jpe?g|gif|webp|avif|svg|ico|css|m?js|map|json|xml|woff2?|ttf|eot|mp4|webm)$/i', $domain)) {
      return null;
    }

    $char = mb_substr($this->mask_character, 0, 1, 'UTF-8') ?: '*';
    if (preg_match('/^' . preg_quote($char, '/') . '+$/u', $prefix)) {
      return null;
    }

    $length     = $this->mask_length === 0 ? strlen($prefix) : $this->mask_length;
    $mask_chars = str_repeat($char, $length);
    $hint       = trim($this->hint_text);
    $suffix     = '@' . $domain . ($hint !== '' && strtoupper($hint) !== 'NULL' ? ' ' . $hint : '');

    return [
      'base_masked' => $mask_chars . '@' . $domain,
      'masked_html' => '<span class="cryptomail-masked-email"><span class="cryptomail-mask">'
        . esc_html($mask_chars)
        . '</span>'
        . esc_html($suffix)
        . '</span>',
    ];
  }

  private function merge_attribute(string $attrs, string $name, string $extra): string
  {
    $pattern = '/\s' . $name . '=(["\'])([^"\']*)\1/i';
    if (preg_match($pattern, $attrs, $rm)) {
      $values = array_unique(preg_split('/\s+/', trim($rm[2] . ' ' . $extra), -1, PREG_SPLIT_NO_EMPTY));
      $merged = implode(' ', $values);
      return preg_replace_callback($pattern, static fn() => ' ' . $name . '="' . $merged . '"', $attrs, 1) ?? $attrs;
    }
    return $attrs . ' ' . $name . '="' . $extra . '"';
  }

  /** Encrypts the payload using Authenticated Encryption (AES-256-GCM) bound to the site's home_url() */
  private function encode(string $string): string
  {
    if (!function_exists('openssl_encrypt')) {
      return '';
    }

    if ($this->reveal_all_matching && isset($this->encoded_cache[$string])) {
      return $this->encoded_cache[$string];
    }

    $iv  = random_bytes(12);
    $tag = '';
    $aad = self::CIPHER_AAD;

    $ciphertext = openssl_encrypt(
      $string,
      'aes-256-gcm',
      $this->raw_key,
      OPENSSL_RAW_DATA,
      $iv,
      $tag,
      $aad,
      16
    );

    if ($ciphertext === false) {
      return '';
    }

    $encoded = base64_encode($iv . $tag . $ciphertext);

    if ($this->reveal_all_matching) {
      $this->encoded_cache[$string] = $encoded;
    }

    return $encoded;
  }

  private function replace_link(array $m): string
  {
    $before_attrs = $m[2];
    $mailto_raw   = $m[4];
    $after_attrs  = $m[5];
    $inner_html   = $m[6];

    $mailto_raw = html_entity_decode($mailto_raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $mailto_raw = str_replace(["\r", "\n"], ["%0D", "%0A"], $mailto_raw);

    $segments = explode('?', $mailto_raw, 2);
    $email    = $segments[0];
    $query    = isset($segments[1]) ? $segments[1] : '';

    $mask = $this->prepare_mask($email);
    if ($mask === null) {
      return $m[0];
    }

    $base_masked = $mask['base_masked'];
    $masked_html = $mask['masked_html'];

    $payload = $email . ($query !== '' ? '?' . $query : '');
    $encoded = $this->encode($payload);

    if ($encoded === '') {
      return $m[0]; // Encryption unavailable: leave the original markup untouched.
    }

    // Replace email inside visible text nodes with the masked HTML, and inside child tag attributes with plain mask
    $masked_inner = preg_replace('/<[^>]*+>(*SKIP)(*F)|' . preg_quote($email, '/') . '/i', $masked_html, $inner_html) ?? $inner_html;
    $is_text_link = ($masked_inner !== $inner_html);
    $escaped_mask = esc_attr($base_masked);
    $masked_inner = str_ireplace($email, $escaped_mask, $masked_inner);
    $attrs = str_ireplace($email, $escaped_mask, $before_attrs . $after_attrs);

    $attrs = $this->merge_attribute($attrs, 'rel', 'nofollow noindex');

    if ($is_text_link) {
      $attrs = $this->merge_attribute($attrs, 'class', 'cryptomail-text-link');
    }

    return '<a' . $attrs . ' href="#" data-cryptomail-payload="' . esc_attr($encoded) . '">' . $masked_inner . '</a>';
  }

  private function replace_plain_email(array $m): string
  {
    $email = $m[2];

    $mask = $this->prepare_mask($email);
    if ($mask === null) {
      return $m[0];
    }

    $encoded = $this->encode($email);
    if ($encoded === '') {
      return $m[0]; // Encryption unavailable: leave the original markup untouched.
    }

    // Accessible anchor link to support keyboard navigation (Tab/Enter/Space)
    return sprintf(
      '<a href="#" class="cryptomail-text-link cryptomail-plain-email" rel="nofollow noindex" data-cryptomail-payload="%s" aria-label="%s">%s</a>',
      esc_attr($encoded),
      esc_attr__('Protected email address', 'crypto-mailto-defender'),
      $mask['masked_html']
    );
  }

  /**
   * Validates Proof-of-Work & human telemetry, and atomically records anti-replay + rate-limit in a single cache/DB operation.
   *
   * @return int 200 = valid, 403 = bot/replay blocked, 429 = rate limit exceeded
   */
  private function verify_and_guard(string $payload, string $proof, string $token, string $ip): int
  {
    if ($proof === '' || $token === '' || !hash_equals($this->get_client_token(), $token)) {
      return 403;
    }

    $decoded = base64_decode($proof, true);
    $parts   = $decoded !== false ? explode('|', $decoded) : [];
    if (count($parts) !== 6) {
      return 403;
    }

    foreach ($parts as $part) {
      if (!ctype_digit($part)) {
        return 403;
      }
    }

    [$ts, $hold_ms, $dom_age, $i_mask, $hw_score, $pow_nonce] = $parts;
    if (abs(time() - (int) $ts) > 300) {
      return 403;
    }

    $min_age  = $this->strict_protection ? 80 : 0;
    $min_mask = $this->strict_protection ? 7 : 3;
    if ((int) $hold_ms < 4 || (int) $hold_ms > 25000 || (int) $dom_age < $min_age || (int) $hw_score < 3 || ((int) $i_mask & $min_mask) !== $min_mask) {
      return 403;
    }

    // Verify Proof-of-Work SHA-256
    $base     = substr($payload, -16) . ":{$ts}:{$hold_ms}:{$dom_age}:{$i_mask}:{$hw_score}:" . substr($token, 0, 12) . ':';
    $pow_diff = $this->get_pow_diff();
    $digest   = hash('sha256', $base . $pow_nonce, true);
    if ((unpack('N', substr($digest, 0, 4))[1] >> (32 - $pow_diff)) !== 0) {
      return 403;
    }

    $ip_hash    = 'rl_' . substr(md5($ip . $this->raw_key), 0, 12);
    $replay_key = 'rp_' . substr(md5($pow_nonce . $ts . $payload), 0, 12);
    $limit      = (int) apply_filters('cryptomail_rate_limit', 25);

    if (wp_using_ext_object_cache()) {
      if (wp_cache_get($replay_key, 'cryptomail')) {
        return 403;
      }
      $attempts = (int) wp_cache_get($ip_hash, 'cryptomail');
      if ($attempts >= $limit) {
        return 429;
      }
      wp_cache_set($replay_key, 1, 'cryptomail', 300);
      wp_cache_set($ip_hash, $attempts + 1, 'cryptomail', MINUTE_IN_SECONDS);
      return 200;
    }

    if (get_transient('cm_' . $replay_key)) {
      return 403;
    }

    $ip_transient = 'cm_' . $ip_hash;
    $attempts     = (int) get_transient($ip_transient);
    if ($attempts >= $limit) {
      return 429;
    }

    set_transient('cm_' . $replay_key, 1, 300);
    set_transient($ip_transient, $attempts + 1, MINUTE_IN_SECONDS);

    return 200;
  }

  /** AJAX endpoint for secure decryption with Rate Limiting & Anti-Bot checks */
  public function ajax_reveal_email(): void
  {
    $this->init_runtime();

    // 1. Verify POST method, Origin / XHR / Sec-Fetch headers and block automated User-Agents
    $method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : '';
    $sfs    = isset($_SERVER['HTTP_SEC_FETCH_SITE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_FETCH_SITE'])) : '';
    $sfm    = isset($_SERVER['HTTP_SEC_FETCH_MODE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_FETCH_MODE'])) : '';
    $sfd    = isset($_SERVER['HTTP_SEC_FETCH_DEST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_FETCH_DEST'])) : '';
    $xhr    = isset($_SERVER['HTTP_X_REQUESTED_WITH']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REQUESTED_WITH'])) : '';
    $ua     = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

    if (
      $method !== 'POST' ||
      ($this->strict_protection && is_ssl() && ($sfs === '' || $sfm === '')) ||
      ($sfs !== '' && !in_array($sfs, ['same-origin', 'same-site'], true)) ||
      ($sfm !== '' && !in_array($sfm, ['cors', 'same-origin'], true)) ||
      ($sfd !== '' && $sfd !== 'empty') ||
      strtolower($xhr) !== 'xmlhttprequest' ||
      $ua === '' ||
      preg_match('/(?:HeadlessChrome|PhantomJS|SlimerJS|Puppeteer|Playwright|Selenium|WebDriver|Cypress|Splash|curl|wget|python|scrapy|go-http-client|axios|node-fetch|undici|httpx|aiohttp|okhttp|libwww|mechanize|java|ruby|perl|postman|insomnia|zgrab|masscan|httrack|gptbot|claudebot|bytespider|ccbot|perplexitybot|amazonbot|applebot-extended|google-extended|meta-externalagent|facebookexternalhit|cohere-ai|diffbot|ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|yandexbot|baiduspider)/i', $ua)
    ) {
      wp_send_json_error(['message' => esc_html__('Unauthorized request.', 'crypto-mailto-defender')], 403);
    }

    if (isset($_SERVER['HTTP_ORIGIN'])) {
      $origin_host = wp_parse_url(esc_url_raw(wp_unslash($_SERVER['HTTP_ORIGIN'])), PHP_URL_HOST);
      $site_host   = wp_parse_url(home_url(), PHP_URL_HOST);
      if (!$origin_host || !$site_host || strtolower($origin_host) !== strtolower($site_host)) {
        wp_send_json_error(['message' => esc_html__('Origin mismatch.', 'crypto-mailto-defender')], 403);
      }
    }

    // 2. Extract and validate parameters
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $payload = isset($_POST['payload']) ? sanitize_text_field(wp_unslash($_POST['payload'])) : '';
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $proof   = isset($_POST['proof']) ? sanitize_text_field(wp_unslash($_POST['proof'])) : '';
    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $token   = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
    if ($payload === '') {
      wp_send_json_error(['message' => esc_html__('No payload provided.', 'crypto-mailto-defender')], 400);
    }

    // 3. Human proof, anti-replay and rate limiting checks in a single pass
    $ip     = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
    $ip     = (string) apply_filters('cryptomail_client_ip', $ip);
    $status = $this->verify_and_guard($payload, $proof, $token, $ip);

    if ($status === 429) {
      wp_send_json_error(['message' => esc_html__('Too many requests. Please slow down.', 'crypto-mailto-defender')], 429);
    }
    if ($status !== 200) {
      wp_send_json_error(['message' => esc_html__('Bot protection triggered.', 'crypto-mailto-defender')], 403);
    }

    // 4. AES-256-GCM Decryption (12 bytes IV + 16 bytes Auth Tag + Ciphertext)
    $data = base64_decode($payload, true);
    if ($data === false || strlen($data) <= 28) {
      wp_send_json_error(['message' => esc_html__('Invalid payload format.', 'crypto-mailto-defender')], 400);
    }

    $iv         = substr($data, 0, 12);
    $tag        = substr($data, 12, 16);
    $ciphertext = substr($data, 28);

    $decrypted = openssl_decrypt(
      $ciphertext,
      'aes-256-gcm',
      $this->raw_key,
      OPENSSL_RAW_DATA,
      $iv,
      $tag,
      self::CIPHER_AAD
    );

    if ($decrypted !== false) {
      wp_send_json_success(['email' => $decrypted]);
    } else {
      wp_send_json_error(['message' => esc_html__('Decryption failed. Integrity check error.', 'crypto-mailto-defender')], 400);
    }
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
    foreach (self::DEFAULTS as $key => $default) {
      register_setting('cryptomail_settings_group', 'cryptomail_' . $key, [
        'type'              => is_int($default) ? 'integer' : 'string',
        'default'           => $default,
        'sanitize_callback' => fn($value) => $this->sanitize_setting($key, $value),
      ]);
    }
  }

  public function purge_page_caches(): void
  {
    // Do NOT call wp_cache_flush() here: it flushes Redis/Memcached object cache, not page caches.
    foreach (['rocket_clean_domain', 'w3tc_flush_all'] as $fn) {
      if (function_exists($fn)) {
        call_user_func($fn);
      }
    }
    if (function_exists('wp_cache_clean_cache')) {
      call_user_func('wp_cache_clean_cache', $GLOBALS['file_prefix'] ?? '', true);
    }
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invoking third-party LiteSpeed Cache hook.
    do_action('litespeed_purge_all');
  }

  public function admin_notices(): void
  {
    if (!current_user_can('manage_options') && !is_super_admin()) {
      return;
    }
    if (!function_exists('openssl_encrypt')) {
      echo '<div class="notice notice-error"><p><strong>Crypto Mailto Defender:</strong> '
        . esc_html__('PHP OpenSSL extension is not installed or enabled. Email protection is currently inactive.', 'crypto-mailto-defender')
        . '</p></div>';
    }
  }

  private function sanitize_setting(string $key, $value)
  {
    if ($key === 'mask_length') {
      return min(absint($value), 50);
    }
    if (is_int(self::DEFAULTS[$key])) {
      return $value ? 1 : 0;
    }
    $value = sanitize_text_field($value);
    return $key === 'mask_character' ? mb_substr($value, 0, 1, 'UTF-8') : $value;
  }

  /** Shared markup renderer for the toggle-switch settings fields */
  private function render_switch_field(string $option_name, int $default, string $label, string $description): void
  {
    $value = get_option($option_name, $default); ?>
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

  public function render_masking_fields(): void
  {
    $char_value = $this->mask_character;
    $len_value  = $this->mask_length;
  ?>
    <div class="cryptomail-masking-fields">
      <div>
        <strong><?php esc_html_e('Masking Character', 'crypto-mailto-defender'); ?></strong><br>
        <input type="text" name="cryptomail_mask_character" value="<?php echo esc_attr($char_value); ?>" maxlength="1" class="cryptomail-input-small">
        <p class="description"><?php esc_html_e('Character used to hide the email (e.g. *, •, -).', 'crypto-mailto-defender'); ?></p>
      </div>
      <div>
        <strong><?php esc_html_e('Mask Length', 'crypto-mailto-defender'); ?></strong><br>
        <input type="number" name="cryptomail_mask_length" value="<?php echo esc_attr($len_value); ?>" min="0" max="50" class="cryptomail-input-small">
        <p class="description"><?php esc_html_e('Fixed number of characters. Set to 0 to match the exact length of the real email prefix.', 'crypto-mailto-defender'); ?></p>
      </div>
    </div>
  <?php
  }

  public function render_hint_field(): void
  {
  ?>
    <strong class="cryptomail-field-label"><?php esc_html_e('Hint Text', 'crypto-mailto-defender'); ?></strong>
    <input type="text" id="cryptomail_hint_text_input" name="cryptomail_hint_text" value="<?php echo esc_attr($this->hint_text); ?>" placeholder="<?php echo esc_attr($this->resolve_hint('(click to reveal)')); ?>">
    <p class="description">
      <?php esc_html_e('Text displayed next to the obfuscated email address on the frontend. Leave empty or type "NULL" to display nothing.', 'crypto-mailto-defender'); ?>
    </p>
  <?php
  }

  /** Renders a titled card containing one or more settings fields */
  private function render_card(string $title, string $subtitle, array $renderers): void
  {
  ?>
    <section class="cryptomail-card">
      <header class="cryptomail-card-header">
        <h3 class="cryptomail-card-title"><?php echo esc_html($title); ?></h3>
        <p class="cryptomail-card-sub"><?php echo esc_html($subtitle); ?></p>
      </header>
      <div class="cryptomail-card-body">
        <?php foreach ($renderers as $renderer) : ?>
          <div class="cryptomail-field">
            <?php call_user_func($renderer); ?>
          </div>
        <?php endforeach; ?>
      </div>
    </section>
  <?php
  }

  public function render_admin_page(): void
  {
    if (!current_user_can('manage_options')) {
      return;
    }
    $this->init_runtime();
  ?>
    <div class="wrap cryptomail-dashboard-wrap">
      <h1 class="screen-reader-text">Crypto Mailto Defender</h1>

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

            $this->render_card(
              __('Protection', 'crypto-mailto-defender'),
              __('Decide how aggressively addresses are hidden from bots and scrapers.', 'crypto-mailto-defender'),
              [
                fn() => $this->render_switch_field('cryptomail_strict_protection', 1, __('Hardware Interaction Required', 'crypto-mailto-defender'), __('When enabled, decryption triggers ONLY upon a verified physical interaction (measuring press duration and blocking automated browser drivers). This prevents headless bots like Puppeteer or Selenium from scraping addresses.', 'crypto-mailto-defender')),
                fn() => $this->render_switch_field('cryptomail_obfuscate_plain', 1, __('Protect Unlinked Emails', 'crypto-mailto-defender'), __('Automatically finds and protects emails that are just written in text, without a mailto: link. Once revealed by the user, they will automatically become clickable mail links.', 'crypto-mailto-defender')),
              ]
            );

            $this->render_card(
              __('Behavior', 'crypto-mailto-defender'),
              __('Control what happens when a visitor interacts with a protected address.', 'crypto-mailto-defender'),
              [
                fn() => $this->render_switch_field('cryptomail_show_loader', 1, __('Show Spinner Loader While Decrypting', 'crypto-mailto-defender'), __('When enabled, replaces the masked characters (e.g. ********) with an animated loading spinner while the email is being decrypted via AJAX.', 'crypto-mailto-defender')),
                fn() => $this->render_switch_field('cryptomail_reveal_all_matching', 1, __('Reveal All Identical Emails Simultaneously', 'crypto-mailto-defender'), __('When enabled, clicking an email address will automatically decrypt and reveal all other occurrences of that exact same email address across the current page.', 'crypto-mailto-defender')),
                fn() => $this->render_switch_field('cryptomail_open_on_first_click', 0, __('Open Mail Client on First Click', 'crypto-mailto-defender'), __('When enabled, clicking an obfuscated email will immediately reveal the address AND open the default email client (1-click action). When disabled, the first click only reveals the text, requiring a second click to send an email.', 'crypto-mailto-defender')),
              ]
            );

            $this->render_card(
              __('Appearance', 'crypto-mailto-defender'),
              __('Customize how protected addresses look before they are revealed.', 'crypto-mailto-defender'),
              [
                [$this, 'render_hint_field'],
                [$this, 'render_masking_fields'],
              ]
            );
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

  /** Set default options and flag redirect in the database upon plugin activation */
  public static function activate(): void
  {
    foreach (self::DEFAULTS as $key => $default) {
      add_option('cryptomail_' . $key, $default);
    }
    add_option('cryptomail_activation_redirect', true);
  }

  /** Redirect the user to the settings page after plugin activation */
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

  /** Clean up all plugin options upon uninstallation */
  public static function uninstall(): void
  {
    foreach (array_keys(self::DEFAULTS) as $key) {
      delete_option('cryptomail_' . $key);
    }
    delete_option(self::SECRET_OPTION);
    delete_option('cryptomail_activation_redirect');
  }
}

register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_uninstall_hook(__FILE__, [Plugin::class, 'uninstall']);

add_action('plugins_loaded', static function (): void {
  new Plugin();
});
