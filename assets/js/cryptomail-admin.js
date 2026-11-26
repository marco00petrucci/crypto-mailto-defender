document.addEventListener('DOMContentLoaded', () => {
    if (typeof cryptomailAdminL10n === 'undefined') return;

    const toggle = document.querySelector('input[type="checkbox"][name="cryptomail_open_on_first_click"]');
    const input = document.getElementById('cryptomail_hint_text_input');
    if (!toggle || !input) return;

    const { defaultHint: single, defaultHintAction: action } = cryptomailAdminL10n;

    toggle.addEventListener('change', () => {
        const [from, to] = toggle.checked ? [single, action] : [action, single];
        input.placeholder = to;
        if (input.value.trim() === from) input.value = to;
    });
});