document.addEventListener('DOMContentLoaded', () => {
  if (typeof cryptomailConfig === 'undefined') return;

  // In-memory cache to prevent duplicate AJAX network calls for identical payloads
  const decryptedCache = new Map();
  const isStrict = cryptomailConfig.strictMode === '1';
  let pressStart = 0;

  // CRC32 lookup table used to sign the client hardware interaction proof
  const crcTable = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    crcTable[i] = c;
  }
  const crc32 = (str) => {
    let crc = 0 ^ (-1);
    for (let i = 0; i < str.length; i++) {
      crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
    }
    return ((crc ^ (-1)) >>> 0).toString();
  };

  const recordPress = (e) => {
    if (isStrict && !e.isTrusted) return;
    if (e.target.closest?.('[data-cryptomail-payload]')) {
      pressStart = performance.now();
    }
  };

  document.addEventListener('pointerdown', recordPress, { capture: true, passive: true });
  document.addEventListener('mousedown', recordPress, { capture: true, passive: true });
  document.addEventListener('touchstart', recordPress, { capture: true, passive: true });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') recordPress(e);
  }, { capture: true, passive: true });

  const buildHumanProof = (payload) => {
    const ts = Math.floor(Date.now() / 1000);
    const rawHold = pressStart > 0 ? Math.max(1, Math.round(performance.now() - pressStart)) : (isStrict ? 0 : 15);
    const holdMs = Math.min(rawHold, 25000);
    pressStart = 0;
    const sig = crc32(`${payload.slice(0, 16)}:${ts}:${holdMs}`);
    return btoa(`${ts}|${holdMs}|${sig}`);
  };

  const applyDecryptedEmail = (trigger, rawPayload) => {
    const emailOnly = rawPayload.split('?')[0];
    const mailtoHref = `mailto:${rawPayload}`;
    const isTextLink = trigger.classList.contains('cryptomail-text-link');

    if (isTextLink) {
      const maskedText = trigger.getAttribute('data-cryptomail-masked');

      if (maskedText) {
        const walker = document.createTreeWalker(trigger, NodeFilter.SHOW_TEXT, null, false);
        let node;
        while ((node = walker.nextNode())) {
          if (node.nodeValue.includes(maskedText)) {
            node.nodeValue = node.nodeValue.split(maskedText).join(emailOnly);
          }
        }
      } else {
        trigger.textContent = emailOnly;
      }

      trigger.classList.add('cryptomail-revealed');
      trigger.removeAttribute('aria-label');
      trigger.removeAttribute('title');
      trigger.removeAttribute('data-cryptomail-masked');

      // Silently copy email address to clipboard on the first reveal for user convenience
      navigator.clipboard?.writeText(emailOnly).catch(() => {});
    }

    trigger.removeAttribute('data-cryptomail-payload');
    delete trigger.dataset.cryptomailDecrypting;

    if (trigger.tagName.toLowerCase() !== 'a') {
      const anchor = document.createElement('a');
      anchor.href = mailtoHref;
      anchor.innerHTML = trigger.innerHTML;
      anchor.className = trigger.className;
      trigger.parentNode.replaceChild(anchor, trigger);
    } else {
      trigger.href = mailtoHref;
    }

    if (!isTextLink) {
      window.location.href = mailtoHref;
    }
  };

  document.addEventListener('click', async (e) => {
    if (isStrict && (!e.isTrusted || navigator.webdriver)) return;

    const trigger = e.target.closest('[data-cryptomail-payload]');
    if (!trigger || trigger.dataset.cryptomailDecrypting) return;

    e.preventDefault();
    const payload = trigger.dataset.cryptomailPayload;

    if (decryptedCache.has(payload)) {
      applyDecryptedEmail(trigger, decryptedCache.get(payload));
      return;
    }

    trigger.dataset.cryptomailDecrypting = 'true';

    try {
      const formData = new FormData();
      formData.append('action', 'cryptomail_reveal');
      formData.append('nonce', cryptomailConfig.nonce || '');
      formData.append('payload', payload);
      formData.append('proof', buildHumanProof(payload));

      const response = await fetch(cryptomailConfig.ajaxUrl, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body: formData
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();

      if (!result.success) {
        throw new Error(result.data?.message || 'Decryption failed by server');
      }

      decryptedCache.set(payload, result.data.email);
      applyDecryptedEmail(trigger, result.data.email);

    } catch (err) {
      console.error(`Crypto Mailto Defender: ${cryptomailConfig.errorMsg}`, err);
      delete trigger.dataset.cryptomailDecrypting;
    }
  }, true);
});