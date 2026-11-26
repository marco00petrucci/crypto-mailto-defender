const initCryptoMailto = () => {
  if (typeof cryptomailConfig === 'undefined' || !window.crypto?.subtle) return;

  const decryptedCache = new Map();
  const hoveredTargets = new WeakSet();
  const isStrict = cryptomailConfig.strictMode === '1';
  const openOnFirstClick = cryptomailConfig.openOnFirstClick === '1';
  const revealAll = cryptomailConfig.revealAll === '1';
  const showLoader = cryptomailConfig.showLoader === '1';

  let pressStart = 0;
  let pressTarget = null;
  let lastPointerType = '';
  let lastClickTime = 0;
  let moveCount = 0;
  let lastMoveX = -1;
  let lastMoveY = -1;
  let automationCache = null;

  const hasPointer = 'PointerEvent' in window;
  const moveEvt = hasPointer ? 'pointermove' : 'mousemove';
  const downEvt = hasPointer ? 'pointerdown' : 'mousedown';
  const isNonMousePointer = (pType) => (pType ? pType !== 'mouse' : 'ontouchstart' in window);

  const TRIGGER_SEL = '[data-cryptomail-payload],[data-cryptomail-mailto]';
  const findTrigger = (target) => {
    const match = target instanceof Element ? target.closest(`${TRIGGER_SEL},button`) : null;
    if (!match) return null;
    return match.matches(TRIGGER_SEL) ? match : match.querySelector(TRIGGER_SEL);
  };

  const isAutomatedEnvironment = () => {
    if (automationCache !== null) return automationCache;

    let tamperedWd = false;
    try {
      const wdDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      tamperedWd = Object.prototype.hasOwnProperty.call(navigator, 'webdriver') ||
        Boolean(wdDesc?.get && !/\[native code\]/.test(Function.prototype.toString.call(wdDesc.get)));
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
      (isDesktopChromium && !window.chrome) ||
      navigator.userAgentData?.brands?.some((b) => /Headless/i.test(b.brand)) ||
      /HeadlessChrome|PhantomJS|Electron|SlimerJS|Playwright|Puppeteer/i.test(ua) ||
      window.callPhantom || window._phantom || window.__nightmare ||
      window.domAutomation || window.domAutomationController || window._selenium ||
      window.Cypress || window.__cypress || window.__puppeteer_evaluation_script__ ||
      Object.getOwnPropertyNames(window).some((k) => /^cdc_[a-zA-Z0-9]+|^__(?:webdriver|driver|fxdriver|selenium|playwright|pw)|^_WEBDRIVER_ELEM_CACHE$|^calledSelenium$/.test(k)) ||
      Object.getOwnPropertyNames(document).some((k) => /^\$(?:cdc|wdc)_|^__(?:webdriver|selenium|driver|fxdriver)/.test(k))
    ) {
      return (automationCache = true);
    }

    return (automationCache = false);
  };

  let softwareRendererCache = null;
  const hasSoftwareWebGL = () => {
    if (softwareRendererCache !== null) return softwareRendererCache;
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('webgl2');
      if (gl) {
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        const renderer = (dbg && gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) || gl.getParameter(gl.RENDERER) || '';
        gl.getExtension('WEBGL_lose_context')?.loseContext();
        return (softwareRendererCache = /SwiftShader|llvmpipe|Softpipe|Software Rasterizer|Mesa OffScreen|Basic Render Driver/i.test(renderer));
      }
    } catch { }
    return (softwareRendererCache = false);
  };

  const getHardwareScore = () => {
    if (isAutomatedEnvironment()) return 0;
    const score = 1 +
      (navigator.hardwareConcurrency >= 1 ? 1 : 0) +
      (window.screen?.width > 100 && window.screen?.height > 100 ? 1 : 0) +
      (typeof window.speechSynthesis !== 'undefined' || 'ontouchstart' in window || navigator.maxTouchPoints > 0 ? 1 : 0) -
      (hasSoftwareWebGL() ? 2 : 0);
    return Math.max(0, score);
  };

  if (isStrict) {
    const trackMove = (e) => {
      if (!e.isTrusted) return;
      if (e.clientX !== lastMoveX || e.clientY !== lastMoveY) {
        lastMoveX = e.clientX;
        lastMoveY = e.clientY;
        if (++moveCount >= 3) {
          document.removeEventListener(moveEvt, trackMove, { passive: true });
        }
      }
    };
    document.addEventListener(moveEvt, trackMove, { passive: true });

    const markTargetHover = (e) => {
      if (!e.isTrusted) return;
      const el = findTrigger(e.target);
      if (el) hoveredTargets.add(el);
    };
    document.addEventListener(hasPointer ? 'pointerover' : 'mouseover', markTargetHover, { capture: true, passive: true });
    document.addEventListener('focusin', markTargetHover, { capture: true, passive: true });
  }

  let liveRegion = null;
  let announceTimer = 0;
  let announceRaf = 0;
  const announce = (msg) => {
    if (!msg) return;
    clearTimeout(announceTimer);
    cancelAnimationFrame(announceRaf);
    const isNew = !liveRegion;
    if (isNew) {
      liveRegion = document.createElement('div');
      liveRegion.className = 'cryptomail-sr-only';
      liveRegion.setAttribute('role', 'status');
      liveRegion.setAttribute('aria-live', 'polite');
      liveRegion.setAttribute('aria-atomic', 'true');
      document.body.appendChild(liveRegion);
    }
    liveRegion.textContent = '';
    const commit = () => { liveRegion.textContent = msg; };
    if (isNew) {
      announceTimer = setTimeout(commit, 100);
    } else {
      announceRaf = requestAnimationFrame(commit);
    }
  };

  const enc = new TextEncoder();
  const solvePow = async (baseStr, diff) => {
    const shift = 32 - diff, batch = 256;
    const prefix = enc.encode(baseStr);
    const pLen = prefix.length;
    const buf = new Uint8Array(pLen + 8);
    buf.set(prefix);
    for (let n = 0; n < 4000000; n += batch) {
      const promises = new Array(batch);
      for (let i = 0; i < batch; i++) {
        const s = String(n + i);
        for (let j = 0; j < s.length; j++) buf[pLen + j] = s.charCodeAt(j);
        promises[i] = crypto.subtle.digest('SHA-256', buf.subarray(0, pLen + s.length));
      }
      const out = await Promise.all(promises);
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
      if (on) {
        el.dataset.cryptomailDecrypting = 'true';
        el.setAttribute('aria-busy', 'true');
      } else {
        delete el.dataset.cryptomailDecrypting;
        el.removeAttribute('aria-busy');
      }
      if (showLoader) el.classList.toggle('cryptomail-loading', on);
    });
  };

  const buildHumanProof = async (payload, evt, triggerEl, isKeyEvent) => {
    const nowPerf = performance.now();
    const ts = Math.floor(Date.now() / 1000);
    const hadTrustedPress = pressStart > 0 && pressTarget === triggerEl;
    const rawDelta = hadTrustedPress ? Math.ceil(Math.max(0, nowPerf - pressStart)) : 0;
    const pType = evt.pointerType || (pressTarget === triggerEl ? lastPointerType : '');
    const wasKeyOrAT = isKeyEvent || (evt.detail === 0 && (!pType || (evt.clientX === 0 && evt.clientY === 0)));
    const isTouchOrKey = wasKeyOrAT || isNonMousePointer(pType);
    const holdMs = Math.min(hadTrustedPress ? rawDelta : (isStrict && !wasKeyOrAT ? 0 : 12), 25000);
    const domAge = Math.min(Math.max(0, Math.round(nowPerf)), 3600000);
    pressStart = 0;
    pressTarget = null;
    lastPointerType = '';

    const boundEl = triggerEl.closest('button') || triggerEl;
    const inRect = (r) =>
      r.width > 0 && r.height > 0 &&
      evt.clientX >= r.left - 5 && evt.clientX <= r.right + 5 &&
      evt.clientY >= r.top - 5 && evt.clientY <= r.bottom + 5;
    const targetEl = evt.target instanceof Element && boundEl.contains(evt.target)
      ? evt.target
      : null;
    const insideBounds = !isStrict || wasKeyOrAT ||
      inRect(boundEl.getBoundingClientRect()) ||
      (targetEl !== null && inRect(targetEl.getBoundingClientRect()));

    const interactionMask =
      (insideBounds ? 1 : 0) |
      (((wasKeyOrAT || (hadTrustedPress && (moveCount >= 3 || isTouchOrKey))) || !isStrict) ? 2 : 0) |
      ((hoveredTargets.has(triggerEl) || wasKeyOrAT || !isStrict) ? 4 : 0) |
      (wasKeyOrAT ? 8 : 0);

    setLoading(triggerEl, payload, true);

    const hwScore = getHardwareScore();
    const tokenPrefix = (cryptomailConfig.token || '').slice(0, 12);
    const powDiff = parseInt(cryptomailConfig.powDiff || '10', 10);
    const baseStr = `${payload.slice(-16)}:${ts}:${holdMs}:${domAge}:${interactionMask}:${hwScore}:${tokenPrefix}:`;
    const powNonce = await solvePow(baseStr, powDiff);
    return btoa(`${ts}|${holdMs}|${domAge}|${interactionMask}|${hwScore}|${powNonce}`);
  };

  const applyDecryptedEmail = (trigger, rawPayload, payload) => {
    const qIdx = rawPayload.indexOf('?');
    const email = qIdx === -1 ? rawPayload : rawPayload.slice(0, qIdx);
    const embeddedQuery = qIdx === -1 ? '' : rawPayload.slice(qIdx + 1);
    const wasTextLink = trigger.classList.contains('cryptomail-text-link');
    const buildHref = (el) => {
      const q = el.dataset.cryptomailQuery || embeddedQuery;
      return `mailto:${email}${q ? `?${q}` : ''}`;
    };
    const triggerHref = buildHref(trigger);

    setLoading(trigger, payload, false);

    targetsFor(trigger, payload).forEach((el) => {
      const href = buildHref(el);
      if (el.classList.contains('cryptomail-text-link')) {
        const spans = el.querySelectorAll('.cryptomail-masked-email');
        if (spans.length) {
          spans.forEach((s) => s.replaceWith(email));
        } else {
          el.textContent = email;
        }
        el.classList.add('cryptomail-revealed');
      }
      if (el.dataset.cryptomailError) {
        if ('cryptomailOrigTitle' in el.dataset) {
          el.title = el.dataset.cryptomailOrigTitle;
          delete el.dataset.cryptomailOrigTitle;
        } else {
          el.removeAttribute('title');
        }
        delete el.dataset.cryptomailError;
      }
      const maskedAttr = el.dataset.cryptomailMaskedAttr;
      if (maskedAttr) {
        [el, ...el.querySelectorAll('[aria-label],[title],[alt]')].forEach((node) => {
          ['aria-label', 'title', 'alt'].forEach((attr) => {
            const val = node.getAttribute(attr);
            if (val && val.includes(maskedAttr)) {
              node.setAttribute(attr, val.split(maskedAttr).join(email));
            }
          });
        });
        delete el.dataset.cryptomailMaskedAttr;
      }
      if (el.dataset.cryptomailRole) {
        el.removeAttribute('role');
        delete el.dataset.cryptomailRole;
      }
      el.removeAttribute('data-cryptomail-payload');
      delete el.dataset.cryptomailQuery;
      if (el.tagName === 'A') {
        el.href = href;
      } else {
        el.dataset.cryptomailMailto = href;
      }
    });

    if (!wasTextLink || openOnFirstClick) {
      window.location.href = triggerHref;
    } else if (cryptomailConfig.revealedMsg) {
      announce(cryptomailConfig.revealedMsg.replace('%s', email));
    }
  };

  const activateTrigger = async (e, isKeyEvent = false) => {
    const trigger = findTrigger(e.target);
    if (!trigger) return;
    if (trigger.dataset.cryptomailDecrypting) {
      e.preventDefault();
      return;
    }

    if (trigger.dataset.cryptomailMailto) {
      e.preventDefault();
      window.location.href = trigger.dataset.cryptomailMailto;
      return;
    }

    e.preventDefault();

    if (isStrict && (!e.isTrusted || document.visibilityState !== 'visible' || isAutomatedEnvironment())) {
      announce(cryptomailConfig.errorMsg);
      return;
    }

    const now = performance.now();
    if (isStrict && now - lastClickTime < 120) return;
    lastClickTime = now;

    const payload = trigger.dataset.cryptomailPayload;
    if (!payload) return;

    if (decryptedCache.has(payload)) {
      pressStart = 0;
      pressTarget = null;
      lastPointerType = '';
      applyDecryptedEmail(trigger, decryptedCache.get(payload), payload);
      return;
    }

    let serverMsg = '';
    try {
      const body = new URLSearchParams({
        action: 'cryptomail_reveal',
        token: cryptomailConfig.token || '',
        payload,
        proof: await buildHumanProof(payload, e, trigger, isKeyEvent)
      });

      const res = await fetch(cryptomailConfig.ajaxUrl, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body,
        credentials: 'same-origin'
      });

      const result = await res.json();
      if (!res.ok || !result.success) {
        serverMsg = result?.data?.message || '';
        throw new Error(serverMsg || cryptomailConfig.errorMsg);
      }

      decryptedCache.set(payload, result.data.email);
      applyDecryptedEmail(trigger, result.data.email, payload);
    } catch {
      setLoading(trigger, payload, false);
      const msg = serverMsg || cryptomailConfig.errorMsg;
      if (!trigger.dataset.cryptomailError && trigger.hasAttribute('title')) {
        trigger.dataset.cryptomailOrigTitle = trigger.title;
      }
      trigger.title = msg;
      trigger.dataset.cryptomailError = '1';
      announce(msg);
    }
  };

  document.addEventListener(downEvt, (e) => {
    if ((isStrict && !e.isTrusted) || e.button !== 0) return;
    const el = findTrigger(e.target);
    if (!el) return;
    pressTarget = el;
    lastPointerType = e.pointerType || '';
    if (isNonMousePointer(lastPointerType)) {
      hoveredTargets.add(el);
    }
    pressStart = performance.now();
  }, { capture: true, passive: true });

  document.addEventListener('keydown', (e) => {
    if (e.repeat || e.ctrlKey || e.metaKey || e.altKey || e.shiftKey || (isStrict && !e.isTrusted)) return;
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = findTrigger(e.target);
    if (!el) return;
    if (e.key === ' ' && el.getAttribute('role') !== 'button' && !el.closest('button')) return;
    pressTarget = el;
    lastPointerType = '';
    pressStart = performance.now();
    activateTrigger(e, true);
  }, { capture: true });

  document.addEventListener('click', (e) => activateTrigger(e, false), true);
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initCryptoMailto, { once: true });
} else {
  initCryptoMailto();
}