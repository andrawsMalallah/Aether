import '../css/app.css';

import.meta.glob(['../images/*.svg'], { eager: true, query: '?url', import: 'default' });

function restoreForms() {
    document.querySelectorAll('[data-submit-form]').forEach((form) => {
        delete form.dataset.submitted;
        form.querySelectorAll('[data-submit-disabled]').forEach((control) => {
            control.disabled = false;
            delete control.dataset.submitDisabled;
        });
        form.querySelectorAll('[data-original-label]').forEach((button) => {
            button.textContent = button.dataset.originalLabel;
            delete button.dataset.originalLabel;
        });
    });
}

window.addEventListener('pageshow', restoreForms);

document.querySelectorAll('[data-submit-form]').forEach((form) => {
    form.addEventListener('submit', (event) => {
        if (form.dataset.submitted) {
            event.preventDefault();
            return;
        }
        form.dataset.submitted = 'true';
        form.querySelectorAll('button[type="submit"]').forEach((button) => {
            button.dataset.originalLabel = button.textContent;
            button.textContent = 'Processing…';
        });
        // Native submission must serialize successful controls before they are disabled.
        setTimeout(() => {
            form.querySelectorAll('input, button').forEach((control) => {
                if (!control.disabled) {
                    control.disabled = true;
                    control.dataset.submitDisabled = 'true';
                }
            });
        }, 0);
    });
});
