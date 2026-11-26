document.addEventListener('DOMContentLoaded', () => {
    const l10n = typeof cryptomailAdminL10n !== 'undefined' ? cryptomailAdminL10n : {};
    const form = document.querySelector('.cryptomail-main-col form');
    const hintInput = document.getElementById('cryptomail_hint_text_input');

    // 1. Auto-save queue & toast feedback
    const toast = document.getElementById('cryptomail_save_toast');
    const toastIcon = toast?.querySelector('.cryptomail-toast-icon');
    const toastText = toast?.querySelector('.cryptomail-toast-text');
    const toastRetry = toast?.querySelector('.cryptomail-toast-retry');

    const pending = new Map();
    const lastFailed = new Map();
    const timers = new Map();
    const lastValues = new Map();
    let inFlight = false;
    let flushScheduled = false;
    let hideTimer = null;

    const setToast = (state, msg) => {
        if (!toast || !toastText) return;
        clearTimeout(hideTimer);
        toast.hidden = false;
        toast.classList.remove('is-saving', 'is-saved', 'is-error');
        toast.classList.add(`is-${state}`);
        toastText.textContent = msg;
        if (toastRetry) toastRetry.hidden = state !== 'error';

        if (toastIcon) {
            if (state === 'saving') {
                toastIcon.innerHTML = '<span class="cryptomail-toast-spinner" aria-hidden="true"></span>';
            } else if (state === 'saved') {
                toastIcon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 6L9 17L4 12" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
            } else {
                toastIcon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="M12 8V12M12 16H12.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';
            }
        }

        requestAnimationFrame(() => toast.classList.add('is-visible'));

        if (state === 'saved') {
            hideTimer = setTimeout(() => {
                toast.classList.remove('is-visible');
                hideTimer = setTimeout(() => {
                    if (!toast.classList.contains('is-visible')) toast.hidden = true;
                }, 220);
            }, 2400);
        }
    };

    const flushSave = async (keepalive = false) => {
        if (inFlight || pending.size === 0 || !l10n.ajaxUrl || !l10n.nonce) return;

        const batch = new Map(pending);
        pending.clear();
        inFlight = true;
        setToast('saving', l10n.savingText || 'Saving…');

        const body = new URLSearchParams({
            action: 'cryptomail_save_settings',
            nonce: l10n.nonce,
        });
        batch.forEach((val, key) => body.append(`settings[${key}]`, String(val)));

        try {
            const res = await fetch(l10n.ajaxUrl, {
                method: 'POST',
                body,
                credentials: 'same-origin',
                keepalive,
            });
            const data = await res.json();
            if (!res.ok || !data?.success) throw new Error();

            batch.forEach((_, key) => lastFailed.delete(key));
            const saved = data.data?.saved || {};
            Object.entries(saved).forEach(([key, val]) => {
                const field = form?.querySelector(`input[name="cryptomail_${CSS.escape(key)}"]`);
                if (field && field.type !== 'checkbox' && field.type !== 'hidden' && document.activeElement !== field) {
                    const str = String(val);
                    field.value = str;
                    lastValues.set(key, str);
                }
            });

            inFlight = false;
            if (pending.size > 0) {
                flushSave();
            } else {
                setToast('saved', l10n.savedText || 'Changes saved');
            }
        } catch {
            batch.forEach((val, key) => {
                if (!pending.has(key)) lastFailed.set(key, val);
            });
            inFlight = false;
            if (pending.size > 0) {
                flushSave();
            } else {
                setToast('error', l10n.saveErrorText || 'Could not save changes.');
            }
        }
    };

    const queueSave = (key, value, delay = 0) => {
        clearTimeout(timers.get(key));
        timers.delete(key);
        pending.set(key, value);
        lastFailed.delete(key);

        if (delay > 0) {
            timers.set(key, setTimeout(() => {
                timers.delete(key);
                flushSave();
            }, delay));
        } else if (!flushScheduled) {
            flushScheduled = true;
            queueMicrotask(() => {
                flushScheduled = false;
                flushSave();
            });
        }
    };

    const flushAllTimers = (keepalive = false) => {
        timers.forEach((t) => clearTimeout(t));
        timers.clear();
        flushSave(keepalive);
    };

    if (toastRetry) {
        toastRetry.addEventListener('click', () => {
            lastFailed.forEach((val, key) => {
                if (!pending.has(key)) pending.set(key, val);
            });
            lastFailed.clear();
            flushSave();
        });
    }

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') flushAllTimers(true);
    });

    // 2. Toggle switches (instant auto-save + hint placeholder sync)
    if (form) {
        form.addEventListener('change', (e) => {
            const el = e.target;
            if (!(el instanceof HTMLInputElement) || el.type !== 'checkbox' || !el.name.startsWith('cryptomail_')) return;

            const key = el.name.slice('cryptomail_'.length);
            queueSave(key, el.checked ? '1' : '0');

            if (key === 'open_on_first_click' && hintInput && l10n.defaultHint && l10n.defaultHintAction) {
                const [from, to] = el.checked
                    ? [l10n.defaultHint, l10n.defaultHintAction]
                    : [l10n.defaultHintAction, l10n.defaultHint];
                hintInput.placeholder = to;
                if (hintInput.value.trim() === from) {
                    hintInput.value = to;
                    lastValues.set('hint_text', to);
                    queueSave('hint_text', to);
                }
            }
        });
    }

    // 3. Text & number inputs (debounced auto-save + immediate flush on blur)
    ['hint_text', 'mask_character', 'mask_length'].forEach((key) => {
        const input = form?.querySelector(`input[name="cryptomail_${key}"]`);
        if (!input) return;
        lastValues.set(key, input.value);

        input.addEventListener('input', () => {
            if (input.value === lastValues.get(key)) return;
            lastValues.set(key, input.value);
            queueSave(key, input.value, 550);
        });

        input.addEventListener('blur', () => {
            if (timers.has(key)) {
                clearTimeout(timers.get(key));
                timers.delete(key);
                flushSave();
            } else if (input.value !== lastValues.get(key)) {
                lastValues.set(key, input.value);
                queueSave(key, input.value);
            }
        });
    });

    // 4. Target emails / domains chip input
    const widget = document.getElementById('cryptomail_target_emails_widget');
    const hidden = document.getElementById('cryptomail_target_emails_value');
    const box = document.getElementById('cryptomail_tag_box');
    const tagEntry = box?.querySelector('.cryptomail-tag-entry');
    const tagInput = document.getElementById('cryptomail_tag_input');
    const addBtn = document.getElementById('cryptomail_tag_add');
    const badge = document.getElementById('cryptomail_target_mode_badge');
    const errorEl = document.getElementById('cryptomail_target_error');
    if (!widget || !hidden || !box || !tagInput) return;

    const quickAddBtn = widget.querySelector('.cryptomail-quick-add');
    const DOMAIN_SRC = l10n.domainPattern || '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}';
    const DOMAIN_RE = new RegExp(`^${DOMAIN_SRC}$`);
    const EMAIL_RE = new RegExp(`^[a-z0-9_%+-]+(?:\\.[a-z0-9_%+-]+)*@${DOMAIN_SRC}$`);

    let rules = hidden.value ? hidden.value.split(',').map((s) => s.trim()).filter(Boolean) : [];

    const findChip = (value) => box.querySelector(`.cryptomail-chip[data-value="${CSS.escape(value)}"]`);

    const normalizeRule = (raw) => {
        const token = raw.trim().toLowerCase().replace(/^mailto:/i, '');
        if (!token) return null;
        if (EMAIL_RE.test(token)) return token;
        const domain = token.replace(/^\*?@/, '');
        if (DOMAIN_RE.test(domain)) return `@${domain}`;
        return null;
    };

    const showError = (msg) => {
        if (!errorEl) return;
        const hasErr = Boolean(msg);
        errorEl.textContent = msg;
        errorEl.hidden = !hasErr;
        box.classList.toggle('has-error', hasErr);
        tagInput.setAttribute('aria-invalid', hasErr ? 'true' : 'false');
        tagInput.setAttribute(
            'aria-describedby',
            hasErr ? 'cryptomail_target_error cryptomail_target_emails_desc' : 'cryptomail_target_emails_desc'
        );
    };

    const syncUI = () => {
        hidden.value = rules.join(',');

        if (badge) {
            const count = rules.length;
            const targeted = count > 0;
            badge.classList.toggle('is-targeted', targeted);
            badge.classList.toggle('is-all', !targeted);
            const textEl = badge.querySelector('.cryptomail-mode-text');
            if (textEl) {
                if (!targeted) {
                    textEl.textContent = l10n.modeAll || 'All site emails (auto-scan)';
                } else if (count === 1) {
                    textEl.textContent = l10n.modeTargetedOne || 'Targeted only (1 rule)';
                } else {
                    textEl.textContent = (l10n.modeTargetedMany || 'Targeted only (%d rules)').replace('%d', String(count));
                }
            }
        }

        if (quickAddBtn) {
            quickAddBtn.hidden = rules.includes(quickAddBtn.dataset.value);
        }
    };

    const createChipEl = (rule) => {
        const isDomain = rule.startsWith('@');
        const display = isDomain ? `*${rule}` : rule;

        const chip = document.createElement('span');
        chip.className = `cryptomail-chip ${isDomain ? 'is-domain' : 'is-email'}`;
        chip.dataset.value = rule;

        if (isDomain) {
            const kind = document.createElement('span');
            kind.className = 'cryptomail-chip-kind';
            kind.textContent = l10n.domainTag || 'domain';
            chip.appendChild(kind);
        }

        const text = document.createElement('span');
        text.className = 'cryptomail-chip-text';
        text.textContent = display;
        chip.appendChild(text);

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'cryptomail-chip-remove';
        removeBtn.setAttribute('aria-label', (l10n.removeLabel || 'Remove %s').replace('%s', display));
        removeBtn.textContent = '×';
        chip.appendChild(removeBtn);

        return chip;
    };

    const removeRule = (value) => {
        const idx = rules.indexOf(value);
        if (idx === -1) return;
        rules.splice(idx, 1);
        findChip(value)?.remove();
        showError('');
        syncUI();
        queueSave('target_emails', hidden.value);
    };

    const commitTokens = (rawString) => {
        const tokens = rawString.split(/[\r\n,;\s]+/).filter(Boolean);
        if (!tokens.length) return true;

        const invalid = [];
        let hadDuplicate = false;
        let added = false;

        tokens.forEach((raw) => {
            const normalized = normalizeRule(raw);
            if (!normalized) {
                invalid.push(raw);
                return;
            }
            if (rules.includes(normalized)) {
                hadDuplicate = true;
                const existing = findChip(normalized);
                if (existing) {
                    existing.classList.remove('is-pulse');
                    void existing.offsetWidth;
                    existing.classList.add('is-pulse');
                }
                return;
            }
            rules.push(normalized);
            added = true;
            box.insertBefore(createChipEl(normalized), tagEntry || tagInput);
        });

        syncUI();
        if (added) queueSave('target_emails', hidden.value);

        if (invalid.length) {
            tagInput.value = invalid.join(' ');
            showError(l10n.invalidEntry || 'Enter a valid email (info@example.com) or domain (example.com).');
            return false;
        }

        tagInput.value = '';
        showError(hadDuplicate && tokens.length === 1 ? (l10n.duplicateEntry || 'Already in the list.') : '');
        return true;
    };

    const commitInput = () => (tagInput.value.trim() === '' ? true : commitTokens(tagInput.value));

    tagInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ',' || e.key === ';' || e.key === ' ') {
            if (tagInput.value.trim() !== '') {
                e.preventDefault();
                commitInput();
            } else if (e.key === 'Enter') {
                e.preventDefault();
            }
            return;
        }
        if (e.key === 'Backspace' && tagInput.value === '' && rules.length > 0) {
            removeRule(rules[rules.length - 1]);
        }
    });

    tagInput.addEventListener('input', () => {
        if (errorEl && !errorEl.hidden) showError('');
    });

    tagInput.addEventListener('paste', (e) => {
        const text = e.clipboardData?.getData('text') || '';
        if (/[\r\n,;\s]/.test(text) || (tagInput.value.trim() === '' && normalizeRule(text))) {
            e.preventDefault();
            commitTokens(tagInput.value + ' ' + text);
        }
    });

    tagInput.addEventListener('blur', commitInput);

    if (addBtn) {
        addBtn.addEventListener('click', () => {
            commitInput();
            tagInput.focus();
        });
    }

    box.addEventListener('click', (e) => {
        const removeBtn = e.target.closest('.cryptomail-chip-remove');
        if (removeBtn) {
            const chip = removeBtn.closest('.cryptomail-chip');
            if (chip) removeRule(chip.dataset.value);
            tagInput.focus();
            return;
        }
        if (!e.target.closest('button')) {
            tagInput.focus();
        }
    });

    if (quickAddBtn) {
        quickAddBtn.addEventListener('click', () => {
            commitTokens(quickAddBtn.dataset.value || '');
            tagInput.focus();
        });
    }

    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (tagInput.value.trim() !== '' && !commitTokens(tagInput.value)) {
                tagInput.focus();
                return;
            }
            flushAllTimers();
        });
    }
});