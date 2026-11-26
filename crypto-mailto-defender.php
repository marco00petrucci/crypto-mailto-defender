<?php

/**
 * Plugin Name: Crypto Mailto Defender
 * Description: Enterprise spam protection. Encrypts mailto: links server-side with AES-256 and securely decrypts them via AJAX upon human interaction.
 * Version: 1.3.1
 * Author: Marco Petrucci
 * Author URI: https://linktr.ee/marco00petrucci
 * Text Domain: crypto-mailto-defender
 * Requires at least: 6.3
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
  private const VERSION = '1.3.1';
  private const CIPHER_AAD = 'cryptomail_v1';

  private const SETTINGS_SLUG = 'crypto-mailto-defender';
  private const SECRET_OPTION = 'cryptomail_aes_secret';
  private const GUARD_TRANSIENT = 'cryptomail_guard_bucket';
  private const EDITOR_TRANSIENT_PREFIX = 'cryptomail_ed_';
  private const DOMAIN_PATTERN = '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}';
  private const DOMAIN_REGEX = '/^' . self::DOMAIN_PATTERN . '$/';
  private string $raw_key;
  private string $aad = '';

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
    'target_emails'       => '',
  ];

  private string $mask_character = '*';
  private int $mask_length = 8;
  private string $hint_text = '';
  private string $target_emails = '';
  /** @var list<string> Parsed lowercase list of specific emails to protect (empty = scan whole site) */
  private array $target_email_list = [];
  private bool $strict_protection = true;
  private bool $obfuscate_plain = true;
  private bool $open_on_first_click = false;
  private bool $reveal_all_matching = true;
  private bool $show_loader = true;
  private bool $buffer_started = false;
  private bool $initialized = false;
  private bool $cache_purged = false;
  private ?bool $skip_cache = null;

  private const BUILDER_PARAMS = ['elementor-preview', 'elementor_library', 'et_fb', 'et_vb', 'et_pb_preview', 'et_bfb', 'bricks', 'brickspreview', 'fl_builder', 'fl_builder_preview', 'ct_builder', 'ct_inner', 'oxygen', 'oxygen_iframe', 'vc_editable', 'vc_action', 'vcv-action', 'vcv-editable', 'brizy-edit', 'brizy-edit-iframe', 'is-editor-iframe', 'fb-edit', 'fusion_load_nonce', 'builder', 'breakdance', 'breakdance_iframe', 'cs_preview_state', 'cornerstone_preview', 'cs-render', 'tve', 'tar_editor_page', 'zionbuilder-preview', 'zionbuilder-barebone-preview', 'seedprod_builder', 'dslc', 'so_live_editor', 'siteorigin_panels_live_editor', 'td_action', 'lc_action_launch_editing', 'lc_page_editing_mode', 'pagelayer-live', 'kubio-preview', 'colibri-preview', 'mpce-edit', 'op3-editor', 'fse-preview', 'wp-find-template', 'legacy-widget-preview', 'wp_scrape_key', 'gutenberg-frame', 'customize_changeset_uuid', 'wp_customize', 'uxb_iframe'];
  private const BUILDER_ACTION_REGEX = '/^(?:edit|elementor|bricks|fl_builder|ct_|et_|vc_|vcv|brizy|architect|tve|kubio|pagelayer|fusion|breakdance|zion|divi|oxy)/i';
  private const SKIP_AJAX_ACTION_REGEX = '/(?:^|[_-])(?:heartbeat|save|edit|admin|builder|update|delete|install|query-attachments|oembed)(?:$|[_-])/i';

  private function server_var(string $key): string
  {
    return isset($_SERVER[$key]) ? sanitize_text_field(wp_unslash($_SERVER[$key])) : '';
  }

  private function post_var(string $key): string
  {
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified via HMAC token + PoW in verify_and_guard().
    return isset($_POST[$key]) && is_string($_POST[$key]) ? sanitize_text_field(wp_unslash($_POST[$key])) : '';
  }

  private function request_var(string $key, bool $as_key = false): string
  {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if (!isset($_REQUEST[$key]) || !is_string($_REQUEST[$key])) {
      return '';
    }
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    return $as_key ? sanitize_key(wp_unslash($_REQUEST[$key])) : sanitize_text_field(wp_unslash($_REQUEST[$key]));
  }

  private function settings_url(): string
  {
    return admin_url('options-general.php?page=' . self::SETTINGS_SLUG);
  }

  private function get_client_token(): string
  {
    return substr(hash_hmac('sha256', $this->aad, $this->raw_key), 0, 32);
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
    add_action('wp_ajax_cryptomail_save_settings', [$this, 'ajax_save_settings']);

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
    $raw    = is_string($secret) ? base64_decode($secret, true) : false;

    if ($raw === false || strlen($raw) !== 32) {
      $generated = base64_encode(random_bytes(32));
      if (add_option(self::SECRET_OPTION, $generated, '', true)) {
        return $generated;
      }
      $existing = get_option(self::SECRET_OPTION);
      $raw      = is_string($existing) ? base64_decode($existing, true) : false;
      if ($raw !== false && strlen($raw) === 32) {
        return $existing;
      }
      update_option(self::SECRET_OPTION, $generated, true);
      return $generated;
    }
    return $secret;
  }

  private function init_runtime(): void
  {
    if ($this->initialized) {
      return;
    }
    $this->raw_key = (string) base64_decode($this->get_secret(), true);
    $this->aad     = self::CIPHER_AAD . '|' . untrailingslashit((string) get_option('home'));
    foreach (self::DEFAULTS as $key => $default) {
      $val = get_option('cryptomail_' . $key, $default);
      $this->$key = is_int($default) ? ($key === 'mask_length' ? (int) $val : (bool) $val) : (string) $val;
    }
    $this->hint_text         = $this->resolve_hint($this->hint_text);
    $this->target_email_list = $this->parse_target_emails($this->target_emails);
    $this->initialized       = true;
  }

  /**
   * Parses a separated list into unique, valid, lowercase email addresses and "@domain.tld" wildcard rules.
   *
   * @return list<string>
   */
  private function parse_target_emails(string $raw): array
  {
    if (trim($raw) === '') {
      return [];
    }
    $parts = preg_split('/[\r\n,;\s]+/', $raw) ?: [];
    $rules = [];
    foreach ($parts as $part) {
      $token = strtolower(trim($part));
      if ($token === '') {
        continue;
      }
      $token = (string) preg_replace('/^mailto:/i', '', $token);
      if (is_email($token)) {
        $rules[$token] = $token;
        continue;
      }
      $domain = (string) preg_replace('/^\*?@/', '', $token);
      if ($domain !== '' && preg_match(self::DOMAIN_REGEX, $domain)) {
        $rules['@' . $domain] = '@' . $domain;
      }
    }
    return array_values($rules);
  }

  /**
   * Returns only the configured target emails or "@domain" rules actually present in $haystack (longest first).
   *
   * @return list<string>
   */
  private function find_present_targets(string $haystack, bool $check_json_escape = false): array
  {
    $has_escaped = $check_json_escape && strpos($haystack, '\u0040') !== false;
    $present     = [];

    foreach ($this->target_email_list as $rule) {
      if (
        stripos($haystack, $rule) !== false ||
        ($has_escaped && stripos($haystack, str_replace('@', '\u0040', $rule)) !== false)
      ) {
        $present[] = $rule;
      }
    }

    if (count($present) > 1) {
      usort($present, static fn(string $a, string $b): int => strlen($b) <=> strlen($a));
    }

    return $present;
  }

  /**
   * Builds a PCRE alternation matching exact target emails and "@domain.tld" wildcards.
   *
   * @param list<string> $rules
   */
  private function build_targets_regex(array $rules): string
  {
    $domains = [];
    foreach ($rules as $rule) {
      if ($rule !== '' && $rule[0] === '@') {
        $domains[$rule] = true;
      }
    }

    $patterns = [];
    foreach ($rules as $rule) {
      if ($rule === '') {
        continue;
      }
      if ($rule[0] === '@') {
        $patterns[] = '[A-Za-z0-9._%+-]++' . preg_quote($rule, '/');
      } else {
        $at = strpos($rule, '@');
        if ($at !== false && isset($domains[substr($rule, $at)])) {
          continue;
        }
        $patterns[] = preg_quote($rule, '/');
      }
    }

    return implode('|', $patterns);
  }

  /** @return array{0:string,1:string} */
  private function get_default_hints(): array
  {
    return [
      __('(click to reveal)', 'crypto-mailto-defender'),
      __('(click to reveal and send)', 'crypto-mailto-defender'),
    ];
  }

  private function resolve_hint(string $saved): string
  {
    [$plain, $send] = $this->get_default_hints();
    if (in_array($saved, [self::DEFAULTS['hint_text'], '(click to reveal and send)', $plain, $send], true)) {
      return $this->open_on_first_click ? $send : $plain;
    }
    return $saved;
  }

  public function enqueue_admin_assets(string $hook): void
  {
    if ($hook !== 'settings_page_' . self::SETTINGS_SLUG) {
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

    [$default_hint, $default_hint_action] = $this->get_default_hints();

    wp_localize_script('cryptomail-admin-script', 'cryptomailAdminL10n', [
      'defaultHint'       => $default_hint,
      'defaultHintAction' => $default_hint_action,
      'modeAll'           => __('All site emails (auto-scan)', 'crypto-mailto-defender'),
      'modeTargetedOne'   => __('Targeted only (1 rule)', 'crypto-mailto-defender'),
      /* translators: %d: number of configured email/domain rules */
      'modeTargetedMany'  => __('Targeted only (%d rules)', 'crypto-mailto-defender'),
      'domainTag'         => __('domain', 'crypto-mailto-defender'),
      /* translators: %s: email address or domain rule to remove */
      'removeLabel'       => __('Remove %s', 'crypto-mailto-defender'),
      'invalidEntry'      => __('Enter a valid email (info@example.com) or domain (example.com).', 'crypto-mailto-defender'),
      'duplicateEntry'    => __('Already in the list.', 'crypto-mailto-defender'),
      'domainPattern'     => self::DOMAIN_PATTERN,
      'ajaxUrl'           => admin_url('admin-ajax.php'),
      'nonce'             => wp_create_nonce('cryptomail_save_settings'),
      'savingText'        => __('Saving…', 'crypto-mailto-defender'),
      'savedText'         => __('Changes saved', 'crypto-mailto-defender'),
      'saveErrorText'     => __('Could not save changes.', 'crypto-mailto-defender'),
      'retryText'         => __('Retry', 'crypto-mailto-defender'),
    ]);
  }

  public function enqueue_frontend_assets(): void
  {
    if ($this->is_builder_or_editor_context()) {
      return;
    }

    if ($this->can_edit_site()) {
      $ed_key = self::EDITOR_TRANSIENT_PREFIX . get_current_user_id();
      if (get_transient($ed_key) !== false) {
        delete_transient($ed_key);
      }
    }

    $this->init_runtime();

    wp_enqueue_style(
      'cryptomail-frontend-css',
      plugin_dir_url(__FILE__) . 'assets/css/cryptomail-frontend.css',
      [],
      self::VERSION
    );
    wp_style_add_data('cryptomail-frontend-css', 'path', plugin_dir_path(__FILE__) . 'assets/css/cryptomail-frontend.css');

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
      'errorMsg'         => __('Decryption failed. Request blocked.', 'crypto-mailto-defender'),
      /* translators: %s: revealed email address */
      'revealedMsg'      => __('Email revealed: %s', 'crypto-mailto-defender'),
    ]);
  }

  private function can_edit_site(): bool
  {
    return function_exists('current_user_can')
      && (current_user_can('edit_posts') || current_user_can('edit_pages') || current_user_can('edit_theme_options'));
  }

  /**
   * Detects if the current request is inside an editor, customizer, or page builder context to prevent encrypting emails inside editor forms or saving masked HTML into the database.
   */
  private function is_builder_or_editor_context(): bool
  {
    if ($this->skip_cache !== null) {
      return $this->skip_cache;
    }

    $is_admin_page = is_admin() && !wp_doing_ajax();
    $skip          = $is_admin_page
      || is_customize_preview()
      || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST);

    $ed_key = '';

    if (!$skip && $this->can_edit_site()) {
      $user_id = get_current_user_id();
      $ed_key  = $user_id > 0 ? self::EDITOR_TRANSIENT_PREFIX . $user_id : '';

      // phpcs:disable WordPress.Security.NonceVerification.Recommended
      $uri     = $this->server_var('REQUEST_URI');
      $rest_p  = '/' . rest_get_url_prefix() . '/';
      $is_rest = (defined('REST_REQUEST') && REST_REQUEST)
        || isset($_REQUEST['rest_route'])
        || ($uri !== '' && strpos($uri, $rest_p) !== false);

      $context      = $this->request_var('context', true);
      $action       = $this->request_var('action', true);

      // Forminator sends preview_data as "[]", "{}", or "false" on normal frontend AJAX loads
      $has_preview_data = false;
      if (isset($_REQUEST['preview_data'])) {
        if (is_array($_REQUEST['preview_data'])) {
          $has_preview_data = !empty($_REQUEST['preview_data']);
        } elseif (is_string($_REQUEST['preview_data'])) {
          $trimmed          = strtolower(sanitize_text_field(wp_unslash($_REQUEST['preview_data'])));
          $has_preview_data = $trimmed !== '' && !in_array($trimmed, ['false', '0', '[]', '{}', 'null'], true);
        }
      }

      $is_preview = (function_exists('is_preview') && is_preview())
        || (isset($_REQUEST['is_preview']) && filter_var(wp_unslash($_REQUEST['is_preview']), FILTER_VALIDATE_BOOLEAN))
        || (isset($_REQUEST['preview']) && filter_var(wp_unslash($_REQUEST['preview']), FILTER_VALIDATE_BOOLEAN))
        || $has_preview_data;

      $skip = $context === 'edit'
        || $is_rest
        || $is_preview
        || (bool) preg_match(self::BUILDER_ACTION_REGEX, $action)
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
        $query_keys = array_map('sanitize_key', wp_unslash(array_keys($_REQUEST)));
        $sec_dest   = sanitize_key($this->server_var('HTTP_SEC_FETCH_DEST'));
        $has_extra  = isset($_REQUEST['extra']) && is_array($_REQUEST['extra']);
        $referers   = array_filter([
          'http'       => $this->server_var('HTTP_REFERER'),
          'wp'         => $this->request_var('_wp_http_referer'),
          'extra_wp'   => $has_extra && isset($_REQUEST['extra']['_wp_http_referer']) && is_string($_REQUEST['extra']['_wp_http_referer']) ? sanitize_text_field(wp_unslash($_REQUEST['extra']['_wp_http_referer'])) : '',
          'extra_url'  => $has_extra && isset($_REQUEST['extra']['referer_url']) && is_string($_REQUEST['extra']['referer_url']) ? sanitize_text_field(wp_unslash($_REQUEST['extra']['referer_url'])) : '',
          'direct_url' => $this->request_var('referer_url'),
        ]);

        $admin_path                = (string) wp_parse_url(admin_url(), PHP_URL_PATH);
        $has_frontend_http_referer = false;

        if (isset($referers['http'])) {
          $http_ref_path = (string) wp_parse_url($referers['http'], PHP_URL_PATH);
          if ($admin_path === '' || strpos($http_ref_path, $admin_path) !== 0) {
            $has_frontend_http_referer = true;
          }
        }

        if (wp_doing_ajax() || $is_rest || isset($_SERVER['HTTP_X_WP_NONCE']) || $sec_dest !== 'document') {
          foreach ($referers as $referer) {
            $ref_path = (string) wp_parse_url($referer, PHP_URL_PATH);
            if (
              ($admin_path !== '' && strpos($ref_path, $admin_path) === 0 && strpos($ref_path, 'admin-ajax.php') === false) ||
              ($ref_path !== '' && strpos($ref_path, $rest_p) !== false)
            ) {
              $skip = true;
              break;
            }
            $from_referer = [];
            wp_parse_str((string) wp_parse_url($referer, PHP_URL_QUERY), $from_referer);
            $ref_context = isset($from_referer['context']) ? sanitize_key($from_referer['context']) : '';
            $ref_action  = isset($from_referer['action']) ? sanitize_key($from_referer['action']) : '';
            $ref_preview = !empty($from_referer['preview']) || !empty($from_referer['is_preview']) || !empty($from_referer['preview_id']);
            if ($ref_context === 'edit' || $ref_preview || preg_match(self::BUILDER_ACTION_REGEX, $ref_action)) {
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
            || (wp_doing_ajax() && !$has_frontend_http_referer && $ed_key !== '' && (bool) get_transient($ed_key));
        }
      }
      // phpcs:enable WordPress.Security.NonceVerification.Recommended
    }

    $result = (bool) apply_filters('cryptomail_skip_request', $skip);

    // Set editor transient only for actual editor/builder contexts, not generic wp-admin screens
    if ($result && !$is_admin_page && $ed_key !== '' && !get_transient($ed_key)) {
      set_transient($ed_key, 1, 600);
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
      $action = $this->request_var('action', true);
      if (
        $action === '' ||
        $action === 'cryptomail_reveal' ||
        preg_match(self::BUILDER_ACTION_REGEX, $action) ||
        preg_match(self::SKIP_AJAX_ACTION_REGEX, $action)
      ) {
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

    if ($this->is_builder_or_editor_context() || is_feed() || is_robots() || is_trackback()) {
      return $buffer;
    }

    $allowed_ct = wp_doing_ajax() ? '#text/html|json|text/plain#i' : '#text/html|json#i';
    foreach (headers_list() as $header) {
      if (stripos($header, 'content-type:') === 0 && !preg_match($allowed_ct, $header)) {
        return $buffer;
      }
    }

    $this->init_runtime();

    if (!empty($this->target_email_list)) {
      if (empty($this->find_present_targets($buffer, true))) {
        return $buffer;
      }
    } elseif (!preg_match('/[\w.+-]@[\w-]+\.[a-z]/i', $buffer) && strpos($buffer, '\u0040') === false) {
      return $buffer;
    }

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

    if (is_string($data) && strpos($data, '@') !== false && strpos($data, '<') !== false) {
      $new_data = $this->process_html_fragment($data);
      if ($new_data !== $data) {
        $modified = true;
        return $new_data;
      }
    }

    return $data;
  }

  private function skip_tags_pattern(string $tags, bool $skip_any_tag = false): string
  {
    return '(?:<svg\b[^>]*+(?<=\/)>|<(' . $tags . ')\b[^>]*+>.*?<\/\1>|<!--.*?-->' . ($skip_any_tag ? '|<[^>]*+>' : '') . ')(*SKIP)(*F)';
  }

  public function process_html_fragment(string $html): string
  {
    if ($html === '' || strpos($html, '@') === false) {
      return $html;
    }

    $this->init_runtime();

    // Slice off <head>...</head> in 0ms on full HTML documents only (avoids cutting AJAX/JSON fragments)
    $head_prefix = '';
    if (preg_match('/^(?:\xEF\xBB\xBF)?(?:\s|<!--.*?-->)*(?:<!DOCTYPE\b|<html\b|<head\b)/is', $html)) {
      $head_end  = stripos($html, '</head>');
      $slice_pos = $head_end !== false ? ($head_end + 7) : stripos($html, '<body');
      if ($slice_pos !== false) {
        $head_prefix = substr($html, 0, $slice_pos);
        $html        = substr($html, $slice_pos);
        if (strpos($html, '@') === false) {
          return $head_prefix . $html;
        }
      }
    }

    $is_targeted = !empty($this->target_email_list);
    $present     = $is_targeted ? $this->find_present_targets($html) : [];
    if ($is_targeted && empty($present)) {
      return $head_prefix . $html;
    }

    // 1. Process mailto: links (supports quoted and HTML5 unquoted href attributes)
    $mailto_changed = false;
    $targets_re     = '';
    if (stripos($html, 'mailto:') !== false) {
      if ($is_targeted) {
        $targets_re      = $this->build_targets_regex($present);
        $quoted_target   = '((?:' . $targets_re . ')(?:\?(?:(?!\3).)*?)?)\s*';
        $unquoted_target = '((?:' . $targets_re . ')(?:\?[^\s"\'=<>`]*?)?)';
      } else {
        $quoted_target   = '((?:(?!\3).)+?)';
        $unquoted_target = '([^\s"\'=<>`]+)';
      }

      $mailto_href = '(?|(["\'])\s*(?:mailto:\s*)+' . $quoted_target . '\3|()(?:mailto:\s*)+' . $unquoted_target . '(?=[\s>]))';
      $replaced    = preg_replace_callback(
        '/' . $this->skip_tags_pattern('head|script|style|textarea|pre|code|noscript|template|svg') . '|<a\b([^>]*?)\shref\s*=\s*' . $mailto_href . '([^>]*)>(.*?)<\/a>/isS',
        [$this, 'replace_link'],
        $html
      );
      if ($replaced !== null && $replaced !== $html) {
        $html           = $replaced;
        $mailto_changed = true;
      }
    }

    // 2. Process plain text emails (emails inside <button> use <span> to avoid invalid nested interactive <a> elements)
    if ($this->obfuscate_plain && strpos($html, '@') !== false) {
      if ($is_targeted) {
        if ($mailto_changed) {
          $present = $this->find_present_targets($html);
          if (empty($present)) {
            return $head_prefix . $html;
          }
          $targets_re = '';
        }
        if ($targets_re === '') {
          $targets_re = $this->build_targets_regex($present);
        }
        $email_core = $targets_re;
      } else {
        $email_core = '[A-Za-z0-9._%+-]++@' . self::DOMAIN_PATTERN;
      }
      $plain_target = '(?<![A-Za-z0-9._%+-])(' . $email_core . ')(?![A-Za-z0-9-]|\.[A-Za-z0-9-])';

      if (stripos($html, '<button') !== false) {
        $btn_inner_regex = '/' . $this->skip_tags_pattern('a|script|style|svg', true) . '|' . $plain_target . '/isS';
        $html = preg_replace_callback(
          '/' . $this->skip_tags_pattern('head|script|style|textarea|pre|code|noscript|template') . '|<button\b[^>]*+>.*?<\/button>/isS',
          fn(array $bm): string => strpos($bm[0], '@') === false
            ? $bm[0]
            : (preg_replace_callback($btn_inner_regex, fn(array $em): string => $this->replace_plain_email($em, true), $bm[0]) ?? $bm[0]),
          $html
        ) ?? $html;
      }

      $html = preg_replace_callback(
        '/' . $this->skip_tags_pattern('head|title|a|button|script|style|textarea|pre|code|option|select|noscript|template|svg|iframe|object', true) . '|' . $plain_target . '/isS',
        [$this, 'replace_plain_email'],
        $html
      ) ?? $html;
    }

    return $head_prefix . $html;
  }

  /**
   * Validates the email, guards against asset filenames or re-masking, and builds the masked placeholder markup.
   *
   * @return array{attr_masked:string,masked_html:string}|null
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

    $char = mb_substr($this->mask_character, 0, 1, 'UTF-8');
    if ($char === '') {
      $char = '*';
    }
    if (preg_match('/^' . preg_quote($char, '/') . '+$/u', $prefix)) {
      return null;
    }

    $length     = $this->mask_length === 0 ? strlen($prefix) : $this->mask_length;
    $mask_chars = str_repeat($char, $length);
    $hint     = trim($this->hint_text);
    $has_hint = $hint !== '' && strtoupper($hint) !== 'NULL';
    $suffix   = '@' . $domain . ($has_hint ? ' ' . $hint : '');
    $sr_hint  = $has_hint
      ? ''
      : '<span class="cryptomail-sr-only"> ' . esc_html($this->resolve_hint(self::DEFAULTS['hint_text'])) . '</span>';

    /* translators: %s: email domain name */
    $attr_masked = sprintf(__('Protected email at %s', 'crypto-mailto-defender'), $domain);

    return [
      'attr_masked' => $attr_masked,
      'masked_html' => '<span class="cryptomail-masked-email"><span class="cryptomail-mask" aria-hidden="true">'
        . esc_html($mask_chars)
        . '</span><span class="cryptomail-sr-only">'
        . esc_html__('Protected email', 'crypto-mailto-defender')
        . ' </span>'
        . esc_html($suffix)
        . $sr_hint
        . '</span>',
    ];
  }

  private function merge_attribute(string $attrs, string $name, string $extra): string
  {
    $pattern = '/\s' . $name . '\s*=\s*(?|(["\'])([^"\']*)\1|()([^\s"\'=<>`]+))/i';
    if (preg_match($pattern, $attrs, $rm)) {
      $values = array_unique(preg_split('/\s+/', trim($rm[2] . ' ' . $extra), -1, PREG_SPLIT_NO_EMPTY));
      $merged = esc_attr(implode(' ', $values));
      return preg_replace_callback($pattern, static fn(): string => ' ' . $name . '="' . $merged . '"', $attrs, 1) ?? $attrs;
    }
    return $attrs . ' ' . $name . '="' . esc_attr($extra) . '"';
  }

  /** Encrypts the payload using Authenticated Encryption (AES-256-GCM) bound to the site's home_url() */
  private function encode(string $string): string
  {
    if (!function_exists('openssl_encrypt')) {
      return '';
    }

    $cache_key = strtolower($string);
    if (isset($this->encoded_cache[$cache_key])) {
      return $this->encoded_cache[$cache_key];
    }

    $iv  = random_bytes(12);
    $tag = '';

    $ciphertext = openssl_encrypt(
      $string,
      'aes-256-gcm',
      $this->raw_key,
      OPENSSL_RAW_DATA,
      $iv,
      $tag,
      $this->aad,
      16
    );

    if ($ciphertext === false) {
      return '';
    }

    return $this->encoded_cache[$cache_key] = base64_encode($iv . $tag . $ciphertext);
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
    $email    = trim($segments[0]);
    $query    = isset($segments[1]) ? trim($segments[1]) : '';

    $mask = $this->prepare_mask($email);
    if ($mask === null) {
      return $m[0];
    }

    $masked_html = $mask['masked_html'];

    $embed_query = $query !== '' && (strpos($query, '@') !== false || stripos($query, '%40') !== false);
    $encoded     = $this->encode($embed_query ? ($email . '?' . $query) : $email);

    if ($encoded === '') {
      return $m[0]; // Encryption unavailable: leave the original markup untouched.
    }

    // Replace email inside visible text nodes with the masked HTML (callback avoids PCRE $0/\1 backreferences)
    $masked_inner = preg_replace_callback(
      '/<[^>]*+>(*SKIP)(*F)|' . preg_quote($email, '/') . '/i',
      static fn(): string => $masked_html,
      $inner_html
    ) ?? $inner_html;
    $is_text_link       = ($masked_inner !== $inner_html);
    $escaped_attr       = esc_attr($mask['attr_masked']);
    $masked_inner_after = str_ireplace($email, $escaped_attr, $masked_inner);
    $inner_attr_changed = ($masked_inner_after !== $masked_inner);
    $masked_inner       = $masked_inner_after;
    $raw_attrs          = $before_attrs . $after_attrs;
    $attrs              = str_ireplace($email, $escaped_attr, $raw_attrs);
    $attr_changed       = ($attrs !== $raw_attrs) || $inner_attr_changed;

    $attrs = $this->merge_attribute($attrs, 'rel', 'nofollow');

    if ($is_text_link) {
      $attrs = $this->merge_attribute($attrs, 'class', 'cryptomail-text-link');
    }

    $query_attr  = ($query !== '' && !$embed_query) ? ' data-cryptomail-query="' . esc_attr($query) . '"' : '';
    $masked_attr = $attr_changed ? ' data-cryptomail-masked-attr="' . $escaped_attr . '"' : '';
    $role_attr   = ($is_text_link && !$this->open_on_first_click && !preg_match('/(?:^|\s)role\s*=/i', $attrs))
      ? ' role="button" data-cryptomail-role="1"'
      : '';

    return '<a' . $attrs . ' href="#"' . $role_attr . ' data-cryptomail-payload="' . esc_attr($encoded) . '"' . $query_attr . $masked_attr . '>' . $masked_inner . '</a>';
  }

  private function replace_plain_email(array $m, bool $as_span = false): string
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

    $tag         = $as_span ? 'span' : 'a';
    $extra_attrs = $as_span
      ? ''
      : ' href="#" rel="nofollow"' . (!$this->open_on_first_click ? ' role="button" data-cryptomail-role="1"' : '');

    return sprintf(
      '<%1$s%2$s class="cryptomail-text-link cryptomail-plain-email" data-cryptomail-payload="%3$s">%4$s</%1$s>',
      $tag,
      $extra_attrs,
      esc_attr($encoded),
      $mask['masked_html']
    );
  }

  private function validate_human_proof(string $payload, string $proof, string $token): bool
  {
    if ($proof === '' || $token === '' || !hash_equals($this->get_client_token(), $token)) {
      return false;
    }

    $decoded = base64_decode($proof, true);
    $parts   = ($decoded !== false && base64_encode($decoded) === $proof) ? explode('|', $decoded) : [];
    if (count($parts) !== 6) {
      return false;
    }

    foreach ($parts as $part) {
      if (!ctype_digit($part)) {
        return false;
      }
    }

    [$ts, $hold_ms, $dom_age, $i_mask, $hw_score, $pow_nonce] = $parts;
    $skew = time() - (int) $ts;
    if ($skew < -60 || $skew > 120) {
      return false;
    }

    $is_key   = (((int) $i_mask & 8) !== 0);
    $min_hold = $is_key ? 0 : 1;
    $min_age  = $this->strict_protection ? 300 : 0;
    $min_hw   = $this->strict_protection ? 3 : 2;
    $min_mask = $this->strict_protection ? 7 : 3;
    if (
      (int) $hold_ms < $min_hold || (int) $hold_ms > 25000 ||
      (int) $dom_age < $min_age || (int) $dom_age > 3600000 ||
      (int) $hw_score < $min_hw || (int) $hw_score > 4 ||
      (int) $i_mask > 15 || ((int) $i_mask & $min_mask) !== $min_mask
    ) {
      return false;
    }

    $base     = substr($payload, -16) . ":{$ts}:{$hold_ms}:{$dom_age}:{$i_mask}:{$hw_score}:" . substr($token, 0, 12) . ':';
    $pow_diff = $this->get_pow_diff();
    $digest   = hash('sha256', $base . $pow_nonce, true);
    return (unpack('N', substr($digest, 0, 4))[1] >> (32 - $pow_diff)) === 0;
  }

  private function verify_and_guard(string $payload, string $proof, string $token, string $ip): int
  {
    $limit = (int) apply_filters('cryptomail_rate_limit', 25);
    if ($limit <= 0) {
      return 429;
    }

    $ip_hash    = 'rl_' . substr(hash('sha256', $ip . $this->raw_key), 0, 16);
    $replay_key = 'rp_' . substr(hash('sha256', $proof . '|' . $payload), 0, 16);

    if (wp_using_ext_object_cache()) {
      if ((int) wp_cache_get($ip_hash, 'cryptomail') >= $limit) {
        return 429;
      }

      $is_valid  = $this->validate_human_proof($payload, $proof, $token);
      $is_unique = $is_valid && wp_cache_add($replay_key, 1, 'cryptomail', 300);
      $cost      = $is_unique ? 1 : 3;

      if (!wp_cache_add($ip_hash, $cost, 'cryptomail', MINUTE_IN_SECONDS)) {
        if ((int) wp_cache_incr($ip_hash, $cost, 'cryptomail') > $limit) {
          return 429;
        }
      }

      return $is_unique ? 200 : 403;
    }

    $now    = time();
    $bucket = get_transient(self::GUARD_TRANSIENT);
    $bucket = is_array($bucket) ? $bucket : ['rp' => [], 'rl' => []];
    $rp     = isset($bucket['rp']) && is_array($bucket['rp'])
      ? array_filter($bucket['rp'], static fn($exp): bool => (int) $exp > $now)
      : [];
    $rl     = isset($bucket['rl']) && is_array($bucket['rl'])
      ? array_filter($bucket['rl'], static fn($row): bool => is_array($row) && (int) ($row['e'] ?? 0) > $now)
      : [];

    $entry = $rl[$ip_hash] ?? ['c' => 0, 'e' => $now + MINUTE_IN_SECONDS];
    if ((int) $entry['c'] >= $limit) {
      return 429;
    }

    $is_valid  = $this->validate_human_proof($payload, $proof, $token);
    $is_unique = $is_valid && !isset($rp[$replay_key]);

    $entry['c']   = (int) $entry['c'] + ($is_unique ? 1 : 3);
    $rl[$ip_hash] = $entry;
    if ($is_unique) {
      $rp[$replay_key] = $now + 300;
    }

    if (count($rp) > 500) {
      asort($rp);
      $rp = array_slice($rp, -500, null, true);
    }
    if (count($rl) > 500) {
      uasort($rl, static fn(array $a, array $b): int => ((int) $a['e']) <=> ((int) $b['e']));
      $rl = array_slice($rl, -500, null, true);
    }

    set_transient(self::GUARD_TRANSIENT, ['rp' => $rp, 'rl' => $rl], 300);

    return $is_unique ? 200 : 403;
  }

  /** AJAX endpoint for secure decryption with Rate Limiting & Anti-Bot checks */
  public function ajax_reveal_email(): void
  {
    $this->init_runtime();

    // 1. Verify POST method, Origin / Referer / XHR / Sec-Fetch / Content-Type headers and block automated User-Agents
    $method = $this->server_var('REQUEST_METHOD');
    $ct     = $this->server_var('CONTENT_TYPE');
    $lang   = $this->server_var('HTTP_ACCEPT_LANGUAGE');
    $sfs    = $this->server_var('HTTP_SEC_FETCH_SITE');
    $sfm    = $this->server_var('HTTP_SEC_FETCH_MODE');
    $sfd    = $this->server_var('HTTP_SEC_FETCH_DEST');
    $xhr    = $this->server_var('HTTP_X_REQUESTED_WITH');
    $ua     = $this->server_var('HTTP_USER_AGENT');

    $raw_origin   = $this->server_var('HTTP_ORIGIN');
    $raw_referer  = $this->server_var('HTTP_REFERER');
    $sec_ch_ua    = $this->server_var('HTTP_SEC_CH_UA');
    $site_host    = wp_parse_url(home_url(), PHP_URL_HOST);
    $origin_host  = wp_parse_url(esc_url_raw($raw_origin), PHP_URL_HOST) ?: '';
    $referer_host = wp_parse_url(esc_url_raw($raw_referer), PHP_URL_HOST) ?: '';

    $origin_matches  = $origin_host !== '' && $site_host && strtolower($origin_host) === strtolower($site_host);
    $referer_matches = $referer_host !== '' && $site_host && strtolower($referer_host) === strtolower($site_host);
    $expects_sfs     = is_ssl() && (bool) preg_match('/(?:(?:Chrome|Chromium|Edg)\/(?:[89]\d|[1-9]\d{2,})|Firefox\/(?:9\d|[1-9]\d{2,})|Version\/(?:1[7-9]|[2-9]\d)\.\d+[^\n]*Safari\/)/i', $ua);

    if (
      $method !== 'POST' ||
      stripos($ct, 'application/x-www-form-urlencoded') !== 0 ||
      ($this->strict_protection && $lang === '') ||
      ($this->strict_protection && $expects_sfs && ($sfs === '' || $sfm === '' || $sfd === '')) ||
      (($this->strict_protection || $sfs === '') && !$origin_matches && !$referer_matches) ||
      ($sfs !== '' && !in_array($sfs, ['same-origin', 'same-site'], true)) ||
      ($sfm !== '' && !in_array($sfm, ['cors', 'same-origin'], true)) ||
      ($sfd !== '' && $sfd !== 'empty') ||
      strtolower($xhr) !== 'xmlhttprequest' ||
      ($sec_ch_ua !== '' && stripos($sec_ch_ua, 'headless') !== false) ||
      $ua === '' ||
      preg_match('/(?:HeadlessChrome|Headless|PhantomJS|SlimerJS|Puppeteer|Playwright|Selenium|WebDriver|Cypress|Splash|curl|wget|python|urllib|scrapy|go-http-client|colly|axios|node-fetch|undici|deno\/|bun\/|got\s|superagent|guzzlehttp|httpx|aiohttp|okhttp|libwww|mechanize|faraday|httpie|k6\/|locust|powershell|java\/|ruby|perl|postman|insomnia|zgrab|masscan|httrack|lighthouse|screaming\s?frog|firecrawl|crawl4ai|apify|googlebot|bingbot|duckduckbot|duckassistbot|applebot|gptbot|oai-searchbot|chatgpt-user|claudebot|anthropic-ai|mistralai-user|deepseekbot|bytespider|ccbot|perplexitybot|amazonbot|google-extended|meta-externalagent|meta-externalfetcher|facebookexternalhit|cohere-ai|diffbot|ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|blexbot|dataforseobot|seznambot|yeti\/|yandexbot|baiduspider)/i', $ua)
    ) {
      wp_send_json_error(['message' => __('Unauthorized request.', 'crypto-mailto-defender')], 403);
    }

    if (($raw_origin !== '' && !$origin_matches) || ($raw_referer !== '' && !$referer_matches)) {
      wp_send_json_error(['message' => __('Origin mismatch.', 'crypto-mailto-defender')], 403);
    }

    // 2. Extract and validate parameters before touching rate-limit / anti-replay storage
    $payload = $this->post_var('payload');
    $proof   = $this->post_var('proof');
    $token   = $this->post_var('token');
    if (
      $payload === '' ||
      strlen($payload) > 8192 ||
      $proof === '' ||
      strlen($proof) > 128 ||
      strlen($token) !== 32 ||
      !preg_match('/^[A-Za-z0-9+\/=]+$/', $payload) ||
      !preg_match('/^[A-Za-z0-9+\/=]+$/', $proof)
    ) {
      wp_send_json_error(['message' => __('Invalid request parameters.', 'crypto-mailto-defender')], 400);
    }

    $data = base64_decode($payload, true);
    if ($data === false || strlen($data) <= 28 || base64_encode($data) !== $payload) {
      wp_send_json_error(['message' => __('Invalid payload format.', 'crypto-mailto-defender')], 400);
    }

    // 3. Human proof, anti-replay and rate limiting checks in a single pass
    $ip     = $this->server_var('REMOTE_ADDR') ?: 'unknown';
    $ip     = (string) apply_filters('cryptomail_client_ip', $ip);
    $status = $this->verify_and_guard($payload, $proof, $token, $ip);

    if ($status === 429) {
      wp_send_json_error(['message' => __('Too many requests. Please slow down.', 'crypto-mailto-defender')], 429);
    }
    if ($status !== 200) {
      wp_send_json_error(['message' => __('Bot protection triggered.', 'crypto-mailto-defender')], 403);
    }

    // 4. AES-256-GCM Decryption (12 bytes IV + 16 bytes Auth Tag + Ciphertext)
    if (!function_exists('openssl_decrypt')) {
      wp_send_json_error(['message' => __('Decryption unavailable.', 'crypto-mailto-defender')], 500);
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
      $this->aad
    );

    if ($decrypted !== false) {
      wp_send_json_success(['email' => $decrypted]);
    } else {
      wp_send_json_error(['message' => __('Decryption failed. Integrity check error.', 'crypto-mailto-defender')], 400);
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
      self::SETTINGS_SLUG,
      [$this, 'render_admin_page']
    );
  }

  public function ajax_save_settings(): void
  {
    check_ajax_referer('cryptomail_save_settings', 'nonce');

    if (!current_user_can('manage_options')) {
      wp_send_json_error(['message' => __('Permission denied.', 'crypto-mailto-defender')], 403);
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified above; values sanitized via sanitize_setting().
    $raw_settings = isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : [];
    if (empty($raw_settings)) {
      wp_send_json_error(['message' => __('No settings provided.', 'crypto-mailto-defender')], 400);
    }

    $saved = [];
    foreach ($raw_settings as $key => $value) {
      if (!is_string($key) || !array_key_exists($key, self::DEFAULTS) || is_array($value)) {
        continue;
      }
      $sanitized = $this->sanitize_setting($key, $value);
      update_option('cryptomail_' . $key, $sanitized);
      $saved[$key] = $sanitized;
    }

    if (empty($saved)) {
      wp_send_json_error(['message' => __('No valid settings provided.', 'crypto-mailto-defender')], 400);
    }

    wp_send_json_success(['saved' => $saved]);
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
    if ($this->cache_purged) {
      return;
    }
    $this->cache_purged = true;

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
    $home_scheme = (string) wp_parse_url(home_url(), PHP_URL_SCHEME);
    $host        = (string) wp_parse_url(home_url(), PHP_URL_HOST);
    if ($home_scheme !== 'https' && !in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
      echo '<div class="notice notice-warning"><p><strong>Crypto Mailto Defender:</strong> '
        . esc_html__('HTTPS is required for browser Web Crypto API verification. Visitors on plain HTTP connections will not be able to reveal protected emails.', 'crypto-mailto-defender')
        . '</p></div>';
    }
  }

  /**
   * @param mixed $value
   * @return int|string
   */
  private function sanitize_setting(string $key, $value)
  {
    if ($key === 'mask_length') {
      return min(absint($value), 50);
    }
    if ($key === 'target_emails') {
      $rules = $this->parse_target_emails(sanitize_textarea_field((string) $value));
      return implode(',', $rules);
    }
    if (is_int(self::DEFAULTS[$key])) {
      return $value ? 1 : 0;
    }
    $value = sanitize_text_field($value);
    return $key === 'mask_character' ? mb_substr($value, 0, 1, 'UTF-8') : $value;
  }

  /** Shared markup renderer for the toggle-switch settings fields */
  private function render_switch_field(string $key, string $label, string $description): void
  {
    $option_name = 'cryptomail_' . $key;
    $value       = (int) $this->$key;
    $desc_id     = $option_name . '_desc'; ?>
    <div class="cryptomail-switch-row">
      <div class="cryptomail-switch-text">
        <label for="<?php echo esc_attr($option_name); ?>"><strong><?php echo esc_html($label); ?></strong></label>
        <p id="<?php echo esc_attr($desc_id); ?>" class="description">
          <?php echo esc_html($description); ?>
        </p>
      </div>
      <span class="cryptomail-switch">
        <input type="hidden" name="<?php echo esc_attr($option_name); ?>" value="0">
        <input type="checkbox" role="switch" id="<?php echo esc_attr($option_name); ?>" name="<?php echo esc_attr($option_name); ?>" value="1" aria-describedby="<?php echo esc_attr($desc_id); ?>" <?php checked(1, $value, true); ?>>
        <span class="cryptomail-slider" aria-hidden="true"></span>
      </span>
    </div>
  <?php
  }

  public function render_masking_fields(): void
  {
  ?>
    <div class="cryptomail-masking-fields">
      <div>
        <label for="cryptomail_mask_character"><strong><?php esc_html_e('Masking Character', 'crypto-mailto-defender'); ?></strong></label><br>
        <input type="text" id="cryptomail_mask_character" name="cryptomail_mask_character" value="<?php echo esc_attr($this->mask_character); ?>" maxlength="1" class="cryptomail-input-small" aria-describedby="cryptomail_mask_character_desc">
        <p id="cryptomail_mask_character_desc" class="description"><?php esc_html_e('Character used to hide the email (e.g. *, •, -).', 'crypto-mailto-defender'); ?></p>
      </div>
      <div>
        <label for="cryptomail_mask_length"><strong><?php esc_html_e('Mask Length', 'crypto-mailto-defender'); ?></strong></label><br>
        <input type="number" id="cryptomail_mask_length" name="cryptomail_mask_length" value="<?php echo esc_attr((string) $this->mask_length); ?>" min="0" max="50" class="cryptomail-input-small" aria-describedby="cryptomail_mask_length_desc">
        <p id="cryptomail_mask_length_desc" class="description"><?php esc_html_e('Fixed number of characters. Set to 0 to match the exact length of the real email prefix.', 'crypto-mailto-defender'); ?></p>
      </div>
    </div>
  <?php
  }

  public function render_target_emails_field(): void
  {
    $rules      = $this->target_email_list;
    $count      = count($rules);
    $is_target  = $count > 0;
    $mode_label = $is_target
      ? sprintf(
        /* translators: %d: number of configured email/domain rules */
        _n('Targeted only (%d rule)', 'Targeted only (%d rules)', $count, 'crypto-mailto-defender'),
        $count
      )
      : __('All site emails (auto-scan)', 'crypto-mailto-defender');

    $site_host = strtolower((string) preg_replace('/^www\./i', '', (string) wp_parse_url(home_url(), PHP_URL_HOST)));
    $site_rule = preg_match(self::DOMAIN_REGEX, $site_host) ? '@' . $site_host : '';
  ?>
    <div id="cryptomail_target_emails_widget" class="cryptomail-target-widget">
      <div class="cryptomail-field-head">
        <label for="cryptomail_tag_input" class="cryptomail-field-label"><strong><?php esc_html_e('Protect Specific Emails or Domains (Optional)', 'crypto-mailto-defender'); ?></strong></label>
        <span id="cryptomail_target_mode_badge" class="cryptomail-mode-badge <?php echo $is_target ? 'is-targeted' : 'is-all'; ?>" aria-live="polite" aria-atomic="true">
          <span class="cryptomail-mode-dot" aria-hidden="true"></span>
          <span class="cryptomail-mode-text"><?php echo esc_html($mode_label); ?></span>
        </span>
      </div>

      <input type="hidden" id="cryptomail_target_emails_value" name="cryptomail_target_emails" value="<?php echo esc_attr(implode(',', $rules)); ?>">

      <div class="cryptomail-tag-box" id="cryptomail_tag_box">
        <?php foreach ($rules as $rule) :
          $is_domain = $rule[0] === '@';
          $display   = $is_domain ? '*' . $rule : $rule;
        ?>
          <span class="cryptomail-chip <?php echo $is_domain ? 'is-domain' : 'is-email'; ?>" data-value="<?php echo esc_attr($rule); ?>">
            <?php if ($is_domain) : ?>
              <span class="cryptomail-chip-kind"><?php esc_html_e('domain', 'crypto-mailto-defender'); ?></span>
            <?php endif; ?>
            <span class="cryptomail-chip-text"><?php echo esc_html($display); ?></span>
            <?php
            /* translators: %s: email address or domain rule to remove */
            $remove_aria = sprintf(__('Remove %s', 'crypto-mailto-defender'), $display);
            ?>
            <button type="button" class="cryptomail-chip-remove" aria-label="<?php echo esc_attr($remove_aria); ?>">&times;</button>
          </span>
        <?php endforeach; ?>

        <div class="cryptomail-tag-entry">
          <input
            type="text"
            id="cryptomail_tag_input"
            class="cryptomail-tag-input"
            placeholder="<?php esc_attr_e('Add email (info@example.com) or domain (example.com)…', 'crypto-mailto-defender'); ?>"
            aria-describedby="cryptomail_target_emails_desc"
            autocomplete="off"
            spellcheck="false">
          <button type="button" id="cryptomail_tag_add" class="cryptomail-tag-add"><?php esc_html_e('Add', 'crypto-mailto-defender'); ?></button>
        </div>
      </div>

      <p id="cryptomail_target_error" class="cryptomail-inline-error" role="alert" hidden></p>

      <div class="cryptomail-target-meta">
        <div class="cryptomail-target-examples">
          <span><code>info@example.com</code> <?php esc_html_e('single email', 'crypto-mailto-defender'); ?></span>
          <span><code>example.com</code> <?php esc_html_e('or', 'crypto-mailto-defender'); ?> <code>@example.com</code> <?php esc_html_e('all emails on that domain', 'crypto-mailto-defender'); ?></span>
        </div>
        <?php if ($site_rule !== '') : ?>
          <button
            type="button"
            class="cryptomail-quick-add"
            data-value="<?php echo esc_attr($site_rule); ?>"
            <?php echo in_array($site_rule, $rules, true) ? 'hidden' : ''; ?>>
            <?php
            /* translators: %s: site domain rule starting with @ (e.g. @example.com) */
            echo '+ ' . esc_html(sprintf(__('All *%s', 'crypto-mailto-defender'), $site_rule));
            ?>
          </button>
        <?php endif; ?>
      </div>

      <p id="cryptomail_target_emails_desc" class="description">
        <?php esc_html_e('Leave empty to automatically scan and protect all emails across the site. Adding at least one email or domain disables full-site scanning and protects only matching addresses.', 'crypto-mailto-defender'); ?>
      </p>
    </div>
  <?php
  }

  public function render_hint_field(): void
  {
  ?>
    <label for="cryptomail_hint_text_input" class="cryptomail-field-label"><strong><?php esc_html_e('Hint Text', 'crypto-mailto-defender'); ?></strong></label>
    <input type="text" id="cryptomail_hint_text_input" name="cryptomail_hint_text" value="<?php echo esc_attr($this->hint_text); ?>" placeholder="<?php echo esc_attr($this->resolve_hint(self::DEFAULTS['hint_text'])); ?>" aria-describedby="cryptomail_hint_text_desc">
    <p id="cryptomail_hint_text_desc" class="description">
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
        <h2 class="cryptomail-card-title"><?php echo esc_html($title); ?></h2>
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
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">
              <path d="M16 10H8C6.89543 10 6 10.8954 6 12V16C6 17.1046 6.89543 18 8 18H16C17.1046 18 18 17.1046 18 16V12C18 10.8954 17.1046 10 16 10Z" fill="white" />
              <path d="M12 10V7C12 5.34315 10.6569 4 9 4C7.34315 4 6 5.34315 6 7" stroke="white" stroke-width="2" stroke-linecap="round" />
            </svg>
          </div>
          <div>
            <p class="cryptomail-title" aria-hidden="true"><?php esc_html_e('Crypto Mailto Defender', 'crypto-mailto-defender'); ?></p>
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
                fn() => $this->render_switch_field('strict_protection', __('Hardware Interaction Required', 'crypto-mailto-defender'), __('When enabled, decryption triggers ONLY upon a verified physical interaction (measuring press duration and blocking automated browser drivers). This prevents headless bots like Puppeteer or Selenium from scraping addresses.', 'crypto-mailto-defender')),
                fn() => $this->render_switch_field('obfuscate_plain', __('Protect Unlinked Emails', 'crypto-mailto-defender'), __('Automatically finds and protects emails that are just written in text, without a mailto: link. Once revealed by the user, they will automatically become clickable mail links.', 'crypto-mailto-defender')),
                [$this, 'render_target_emails_field'],
              ]
            );

            $this->render_card(
              __('Behavior', 'crypto-mailto-defender'),
              __('Control what happens when a visitor interacts with a protected address.', 'crypto-mailto-defender'),
              [
                fn() => $this->render_switch_field('show_loader', __('Show Spinner Loader While Decrypting', 'crypto-mailto-defender'), __('When enabled, replaces the masked characters (e.g. ********) with an animated loading spinner while the email is being decrypted via AJAX.', 'crypto-mailto-defender')),
                fn() => $this->render_switch_field('reveal_all_matching', __('Reveal All Identical Emails Simultaneously', 'crypto-mailto-defender'), __('When enabled, clicking an email address will automatically decrypt and reveal all other occurrences of that exact same email address across the current page.', 'crypto-mailto-defender')),
                fn() => $this->render_switch_field('open_on_first_click', __('Open Mail Client on First Click', 'crypto-mailto-defender'), __('When enabled, clicking an obfuscated email will immediately reveal the address AND open the default email client (1-click action). When disabled, the first click only reveals the text, requiring a second click to send an email.', 'crypto-mailto-defender')),
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
            <noscript>
              <div class="cryptomail-noscript-save">
                <button type="submit" class="cryptomail-btn-primary">
                  <?php esc_html_e('Save Configuration', 'crypto-mailto-defender'); ?>
                </button>
              </div>
            </noscript>
          </form>
        </div>
      </div>

      <div id="cryptomail_save_toast" class="cryptomail-toast" role="status" aria-live="polite" aria-atomic="true" hidden>
        <span class="cryptomail-toast-icon" aria-hidden="true"></span>
        <span class="cryptomail-toast-text"></span>
        <button type="button" class="cryptomail-toast-retry" hidden><?php esc_html_e('Retry', 'crypto-mailto-defender'); ?></button>
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
    add_option(self::SECRET_OPTION, base64_encode(random_bytes(32)), '', true);
    add_option('cryptomail_activation_redirect', true);
  }

  /** Redirect the user to the settings page after plugin activation */
  public function redirect_after_activation(): void
  {
    if (wp_doing_ajax() || !current_user_can('manage_options')) {
      return;
    }

    if (get_option('cryptomail_activation_redirect', false)) {
      delete_option('cryptomail_activation_redirect');

      // phpcs:ignore WordPress.Security.NonceVerification.Recommended
      if (!isset($_GET['activate-multi'])) {
        wp_safe_redirect($this->settings_url());
        exit;
      }
    }
  }

  public function add_settings_link(array $links): array
  {
    $settings_link = '<a href="' . esc_url($this->settings_url()) . '">' . esc_html__('Settings', 'crypto-mailto-defender') . '</a>';
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
    delete_transient(self::GUARD_TRANSIENT);
    delete_transient('cm_guard_bucket');

    global $wpdb;
    $like_transient = $wpdb->esc_like('_transient_' . self::EDITOR_TRANSIENT_PREFIX) . '%';
    $like_timeout   = $wpdb->esc_like('_transient_timeout_' . self::EDITOR_TRANSIENT_PREFIX) . '%';
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $like_transient, $like_timeout));
  }
}

register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_uninstall_hook(__FILE__, [Plugin::class, 'uninstall']);

add_action('plugins_loaded', static function (): void {
  new Plugin();
});
