document.addEventListener('DOMContentLoaded', () => {
  if (typeof cryptomailConfig === 'undefined' || !window.crypto?.subtle) return;

  const loadTime = performance.now();
  const decryptedCache = new Map();
  const hoveredTargets = new WeakSet();
  const isStrict = cryptomailConfig.strictMode === '1';
  const openOnFirstClick = cryptomailConfig.openOnFirstClick === '1';
  const revealAll = cryptomailConfig.revealAll === '1';
  const showLoader = cryptomailConfig.showLoader === '1';

  let pressStart = 0;
  let lastClickTime = 0;
  let hasMoved = false;
  let lastKeyboardTrusted = false;
  let automationCache = null;

  const findTrigger = (target) =>
    target?.closest?.('[data-cryptomail-payload]') ||
    target?.closest?.('button')?.querySelector?.('[data-cryptomail-payload]') ||
    null;

  const isAutomatedEnvironment = () => {
    if (automationCache !== null) return automationCache;

    let tamperedWd = false;
    try {
      const wdDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      tamperedWd = Object.hasOwn(navigator, 'webdriver') || !wdDesc || (wdDesc.get && !/\[native code\]/.test(Function.prototype.toString.call(wdDesc.get)));
    } catch {
      tamperedWd = true;
    }

    const ua = navigator.userAgent || '';
    const isDesktopChromium = /Chrome|Chromium/i.test(ua) && !/Mobile|Android/i.test(ua) && !('ontouchstart' in window);

    if (
      navigator.webdriver ||
      tamperedWd ||
      !navigator.languages?.length ||
      (window.outerWidth === 0 && window.outerHeight === 0) ||
      (isDesktopChromium && (!window.chrome || navigator.plugins?.length === 0)) ||
      navigator.userAgentData?.brands?.some((b) => /Headless/i.test(b.brand)) ||
      /HeadlessChrome|PhantomJS|Electron|SlimerJS|Playwright|Puppeteer/i.test(ua) ||
      window.callPhantom || window._phantom || window.__nightmare ||
      window.domAutomation || window.domAutomationController || window._selenium ||
      window.__playwright_evaluation_script__ || window.__pwInitScripts ||
      Object.keys(window).some((k) => /^cdc_[a-zA-Z0-9]+|^__webdriver|^__driver|^__fxdriver/.test(k)) ||
      Object.keys(document).some((k) => /^\$cdc_|^__webdriver/.test(k))
    ) {
      return (automationCache = true);
    }

    try {
      const gl = document.createElement('canvas').getContext('webgl');
      if (gl) {
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        const renderer = (dbg && gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) || '';
        gl.getExtension('WEBGL_lose_context')?.loseContext();
        if (/SwiftShader|llvmpipe|Software Rasterizer|Mesa OffScreen/i.test(renderer)) return (automationCache = true);
      }
    } catch { }

    return (automationCache = false);
  };

  const getHardwareScore = () => {
    if (isAutomatedEnvironment()) return 0;
    return 1 +
      (navigator.hardwareConcurrency >= 1 ? 1 : 0) +
      (window.screen?.width > 100 && window.screen?.height > 100 ? 1 : 0) +
      (typeof window.speechSynthesis !== 'undefined' || 'ontouchstart' in window || navigator.maxTouchPoints > 0 ? 1 : 0);
  };

  const trackMove = (e) => {
    if (e.isTrusted) {
      hasMoved = true;
      document.removeEventListener('pointermove', trackMove, { passive: true });
    }
  };
  document.addEventListener('pointermove', trackMove, { passive: true });

  const markTargetHover = (e) => {
    if (!e.isTrusted) return;
    const el = findTrigger(e.target);
    if (el) hoveredTargets.add(el);
  };
  document.addEventListener('pointerover', markTargetHover, { capture: true, passive: true });
  document.addEventListener('focusin', markTargetHover, { capture: true, passive: true });

  const recordPress = (e) => {
    if (isStrict && !e.isTrusted) return;
    const el = findTrigger(e.target);
    if (!el) return;
    hoveredTargets.add(el);
    pressStart = performance.now();
    lastKeyboardTrusted = e.type === 'keydown' && e.isTrusted;
    if (lastKeyboardTrusted && e.key === ' ') {
      e.preventDefault();
      el.click();
    }
  };

  document.addEventListener('pointerdown', recordPress, { capture: true, passive: true });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') recordPress(e);
  }, { capture: true });

  const enc = new TextEncoder();
  const solvePow = async (baseStr, diff) => {
    const shift = 32 - diff, batch = 256;
    for (let n = 0; n < 4000000; n += batch) {
      const out = await Promise.all(Array.from({ length: batch }, (_, i) =>
        crypto.subtle.digest('SHA-256', enc.encode(baseStr + (n + i)))));
      for (let i = 0; i < batch; i++) {
        if ((new DataView(out[i]).getUint32(0) >>> shift) === 0) return n + i;
      }
    }
    throw new Error('PoW failed');
  };

  const targetsFor = (trigger, payload) =>
    revealAll ? document.querySelectorAll(`[data-cryptomail-payload="${CSS.escape(payload)}"]`) : [trigger];

  const setLoading = (trigger, payload, on) => {
    targetsFor(trigger, payload).forEach((el) => {
      if (on) el.dataset.cryptomailDecrypting = 'true';
      else delete el.dataset.cryptomailDecrypting;
      if (showLoader) el.classList.toggle('cryptomail-loading', on);
    });
  };

  const buildHumanProof = async (payload, clickEvent, triggerEl) => {
    const nowPerf = performance.now();
    const ts = Math.floor(Date.now() / 1000);
    const hadTrustedPress = pressStart > 0;
    const rawDelta = Math.round(nowPerf - pressStart);
    const wasKeyNav = lastKeyboardTrusted && clickEvent.detail === 0;
    const isTouchOrKey = wasKeyNav || clickEvent.pointerType === 'touch' || 'ontouchstart' in window;
    const holdMs = Math.min(hadTrustedPress ? Math.max(4, rawDelta) : (isStrict ? 0 : 12), 25000);
    const domAge = Math.min(Math.max(0, Math.round(nowPerf - loadTime)), 3600000);
    pressStart = 0;
    lastKeyboardTrusted = false;

    const boundEl = triggerEl.closest('button') || triggerEl;
    const rect = boundEl.getBoundingClientRect();
    const insideBounds = !isStrict || wasKeyNav || (
      rect.width > 0 && rect.height > 0 &&
      clickEvent.clientX >= rect.left - 5 && clickEvent.clientX <= rect.right + 5 &&
      clickEvent.clientY >= rect.top - 5 && clickEvent.clientY <= rect.bottom + 5
    );

    const interactionMask =
      (insideBounds ? 1 : 0) |
      (((hadTrustedPress && (hasMoved || isTouchOrKey)) || !isStrict) ? 2 : 0) |
      ((hoveredTargets.has(triggerEl) || !isStrict) ? 4 : 0);

    setLoading(triggerEl, payload, true);

    const hwScore = getHardwareScore();
    const tokenPrefix = (cryptomailConfig.token || '').slice(0, 12);
    const powDiff = parseInt(cryptomailConfig.powDiff || '10', 10);
    const baseStr = `${payload.slice(-16)}:${ts}:${holdMs}:${domAge}:${interactionMask}:${hwScore}:${tokenPrefix}:`;
    const powNonce = await solvePow(baseStr, powDiff);
    return btoa(`${ts}|${holdMs}|${domAge}|${interactionMask}|${hwScore}|${powNonce}`);
  };

  const applyDecryptedEmail = (trigger, rawPayload, payload) => {
    const email = rawPayload.split('?')[0];
    const href = `mailto:${rawPayload}`;
    const wasTextLink = trigger.classList.contains('cryptomail-text-link');

    targetsFor(trigger, payload).forEach((el) => {
      el.classList.remove('cryptomail-loading');
      if (el.classList.contains('cryptomail-text-link')) {
        const spans = el.querySelectorAll('.cryptomail-masked-email');
        if (spans.length) {
          spans.forEach((s) => s.replaceWith(email));
        } else {
          el.textContent = email;
        }
        el.classList.add('cryptomail-revealed');
        el.removeAttribute('aria-label');
        el.removeAttribute('title');
      }
      el.removeAttribute('data-cryptomail-payload');
      delete el.dataset.cryptomailDecrypting;
      el.href = href;
    });

    if (!wasTextLink || openOnFirstClick) {
      window.location.href = href;
    }
  };

  document.addEventListener('click', async (e) => {
    if (isStrict && ((!e.isTrusted && !lastKeyboardTrusted) || isAutomatedEnvironment())) return;

    const trigger = findTrigger(e.target);
    if (!trigger || trigger.dataset.cryptomailDecrypting) return;

    e.preventDefault();
    const now = performance.now();
    if (isStrict && now - lastClickTime < 120) return;
    lastClickTime = now;

    const payload = trigger.dataset.cryptomailPayload;

    if (decryptedCache.has(payload)) {
      applyDecryptedEmail(trigger, decryptedCache.get(payload), payload);
      return;
    }

    try {
      const body = new URLSearchParams({
        action: 'cryptomail_reveal',
        token: cryptomailConfig.token || '',
        payload,
        proof: await buildHumanProof(payload, e, trigger)
      });

      const res = await fetch(cryptomailConfig.ajaxUrl, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body,
        credentials: 'same-origin'
      });

      const result = await res.json();
      if (!res.ok || !result.success) throw new Error();

      decryptedCache.set(payload, result.data.email);
      applyDecryptedEmail(trigger, result.data.email, payload);
    } catch {
      setLoading(trigger, payload, false);
      trigger.title = cryptomailConfig.errorMsg;
    }
  }, true);
});