document.addEventListener('DOMContentLoaded', () => {
  // Ensure the localized configuration object exists
  if (typeof cryptomailConfig === 'undefined') return;

  // Global event listener for all elements with the data-cryptomail-payload attribute
  document.addEventListener('click', async (e) => {
    // Strict Bot Protection: requires user-initiated events to prevent automated scripts from triggering decryption
    if (cryptomailConfig.strictMode === '1' && !e.isTrusted) return;

    const trigger = e.target.closest('[data-cryptomail-payload]');
    if (!trigger || trigger.dataset.cryptomailDecrypting) return;

    e.preventDefault();

    // Set a flag to prevent multiple simultaneous decryption attempts
    trigger.dataset.cryptomailDecrypting = 'true';

    try {
      // Construct the data for the AJAX call
      const formData = new FormData();
      formData.append('action', 'cryptomail_reveal');
      formData.append('nonce', cryptomailConfig.nonce);
      formData.append('payload', trigger.dataset.cryptomailPayload);

      // Secure call to the WordPress Server-Side API
      const response = await fetch(cryptomailConfig.ajaxUrl, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();

      if (!result.success) {
        throw new Error(result.data.message || 'Decryption failed by server');
      }

      const rawPayload = result.data.email;
      const emailOnly = rawPayload.split('?')[0];
      const mailtoHref = `mailto:${rawPayload}`;

      const isTextLink = trigger.classList.contains('cryptomail-text-link');

      if (isTextLink) {
        const maskedText = trigger.getAttribute('data-cryptomail-masked');

        if (maskedText) {
          // Traverse the text nodes safely to avoid breaking the design
          const walker = document.createTreeWalker(trigger, NodeFilter.SHOW_TEXT, null, false);
          let node;
          while ((node = walker.nextNode())) {
            if (node.nodeValue.includes(maskedText)) {
              node.nodeValue = node.nodeValue.split(maskedText).join(emailOnly);
            }
          }
        } else {
          // Safety fallback
          trigger.textContent = emailOnly;
        }

        // Cleans the link once revealed
        trigger.classList.add('cryptomail-revealed');
        trigger.removeAttribute('aria-label');
        trigger.removeAttribute('title');
        trigger.removeAttribute('data-cryptomail-masked');
      }

      // Removes the custom attributes, reverting to a native link
      trigger.removeAttribute('data-cryptomail-payload');
      delete trigger.dataset.cryptomailDecrypting;

      // If the trigger is not an anchor, create one to ensure proper mailto functionality
      if (trigger.tagName.toLowerCase() !== 'a') {
        const anchor = document.createElement('a');
        anchor.href = mailtoHref;
        anchor.innerHTML = trigger.innerHTML;
        anchor.className = trigger.className;
        trigger.parentNode.replaceChild(anchor, trigger);
      } else {
        trigger.href = mailtoHref;
      }

      // Open the email client immediately for icons or buttons
      if (!isTextLink) {
        window.location.href = mailtoHref;
      }

    } catch (err) {
      console.error(`Crypto Mailto Defender: ${cryptomailConfig.errorMsg}`, err);
      delete trigger.dataset.cryptomailDecrypting;
    }
  }, true);
});