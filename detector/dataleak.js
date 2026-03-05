/**
 * ZTBG — Outbound Data Leak Protection v1.0.1
 *
 * Fixes applied (Phases 2, 3, 4, 5):
 *  - ALL innerHTML removed — banner/modal built with safe DOM APIs
 *  - detectionName sanitised with textContent before inserting into DOM
 *  - Paste event listener registered ONCE via guard flag (was re-registered on rescan)
 *  - sendMessage calls wrapped in .catch() — no unhandled rejections
 *  - Stored detections are metadata-only (name + severity, NOT the matched secret value)
 *  - Luhn check: now also rejects strings shorter than 13 digits after stripping spaces
 *  - False positives: API Key / Generic Secret patterns skip strings that look like
 *    hex hashes, version strings, or UUIDs
 *  - No clipboard contents are logged to console
 *  - Banner auto-dismiss timer cleared if banner is manually closed (no leak)
 *  - Modal overlay closes on Escape key
 *  - Style tags for animations injected once per page (idempotency guard)
 *  - PATTERNS array compiled once at module load (not on every event)
 */

(function (global) {
    'use strict';

    // ─── Guard: never run inside the extension popup itself ──────────────────

    if (
        typeof location !== 'undefined' &&
        location.protocol === 'chrome-extension:'
    ) return;

    // ─── Compiled Patterns (built once at load time) ──────────────────────────

    const PATTERNS = Object.freeze([
        {
            name: 'AWS Access Key',
            regex: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/,
            severity: 'critical',
        },
        {
            name: 'JWT Token',
            regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
            severity: 'high',
        },
        {
            name: 'GitHub Personal Token',
            regex: /ghp_[a-zA-Z0-9]{36}/,
            severity: 'critical',
        },
        {
            name: 'GitHub OAuth Token',
            regex: /gho_[a-zA-Z0-9]{36}/,
            severity: 'critical',
        },
        {
            name: 'Private Key Header',
            // Word boundary not available for '---', use context
            regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
            severity: 'critical',
        },
        {
            name: 'Credit Card Number',
            // Requires 13–19 digits with optional spaces/hyphens
            regex: /\b(?:\d[ -]?){13,19}\b/,
            severity: 'high',
            validate: luhnCheck,
        },
        {
            name: 'Stripe Secret Key',
            regex: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/,
            severity: 'critical',
        },
        {
            name: 'Slack Bot Token',
            regex: /xox[baprs]-(?:\d+-)+[a-zA-Z0-9]+/,
            severity: 'high',
        },
        {
            name: 'Bearer Token',
            regex: /\bBearer\s+[a-zA-Z0-9\-._~+/]+=*/i,
            severity: 'high',
        },
        {
            name: 'Google API Key',
            regex: /AIza[0-9A-Za-z\-_]{35}/,
            severity: 'critical',
        },
        {
            name: 'High-Entropy API Key',
            // Long alphanumeric — requires entropy check to avoid false positives
            regex: /[a-zA-Z0-9]{32,45}/,
            severity: 'medium',
            requiresEntropy: true,
        },
    ]);

    // Patterns that look high-entropy but aren't secrets
    const ENTROPY_FP_PATTERNS = [
        /^[0-9a-f]{32}$/i,                    // MD5 hash
        /^[0-9a-f]{40}$/i,                    // SHA1 hash
        /^[0-9a-f]{64}$/i,                    // SHA256 hash
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
        /^\d+\.\d+\.\d+(\.\d+)?$/,           // Version string
    ];

    // ─── Luhn Algorithm ───────────────────────────────────────────────────────

    /**
     * Validate a potential credit card number using the Luhn algorithm.
     * @param {string} numStr - Raw string (may contain spaces/hyphens)
     * @returns {boolean}
     */
    function luhnCheck(numStr) {
        if (typeof numStr !== 'string') return false;
        const digits = numStr.replace(/[\s\-]/g, '');
        // Must be all digits, 13–19 characters
        if (!/^\d{13,19}$/.test(digits)) return false;

        let sum = 0;
        let alternate = false;
        for (let i = digits.length - 1; i >= 0; i--) {
            let n = parseInt(digits[i], 10);
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 === 0;
    }

    // ─── Pattern Scanner ──────────────────────────────────────────────────────

    /**
     * Scan text for sensitive data matches.
     * Returns metadata only — never the matched secret value itself.
     * @param {string} text - Text to scan
     * @returns {Array<{name: string, severity: string}>}
     */
    function scanForSensitiveData(text) {
        if (!text || typeof text !== 'string' || text.trim().length === 0) return [];

        const detections = [];

        for (const pattern of PATTERNS) {
            let match;
            try {
                match = pattern.regex.exec(text);
            } catch (_) {
                continue;
            }
            if (!match) continue;

            // Credit card: Luhn validation
            if (pattern.validate && !pattern.validate(match[0])) continue;

            // High-entropy patterns: require entropy check
            if (pattern.requiresEntropy) {
                const matchedStr = match[0];
                // Skip common non-secret patterns
                if (ENTROPY_FP_PATTERNS.some(p => p.test(matchedStr))) continue;
                // Entropy gate
                if (global.ZTBGEntropy && typeof global.ZTBGEntropy.shannonEntropy === 'function') {
                    if (global.ZTBGEntropy.shannonEntropy(matchedStr) <= 4.5) continue;
                }
            }

            // Store name + severity ONLY — no matched content
            detections.push({ name: pattern.name, severity: pattern.severity });
        }

        return detections;
    }

    // ─── Style injection (idempotent) ─────────────────────────────────────────

    const STYLE_ID = 'ztbg-dataleak-styles';

    function ensureStyles() {
        if (document.getElementById(STYLE_ID)) return;
        const style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent = [
            '@keyframes ztbgSlideDown{from{opacity:0;transform:translateX(-50%) translateY(-20px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}',
            '@keyframes ztbgModalIn{from{opacity:0;transform:translate(-50%,-60%) scale(0.9)}to{opacity:1;transform:translate(-50%,-50%) scale(1)}}',
        ].join('');
        (document.head || document.documentElement).appendChild(style);
    }

    // ─── Safe DOM builder helpers ─────────────────────────────────────────────

    function el(tag, attrs = {}, children = []) {
        const node = document.createElement(tag);
        for (const [k, v] of Object.entries(attrs)) {
            if (k === 'style') node.style.cssText = v;
            else if (k === 'className') node.className = v;
            else if (k === 'textContent') node.textContent = v;
            else node.setAttribute(k, v);
        }
        for (const child of children) {
            if (typeof child === 'string') node.appendChild(document.createTextNode(child));
            else if (child instanceof Node) node.appendChild(child);
        }
        return node;
    }

    // ─── Inline Warning Banner (XSS-safe DOM construction) ───────────────────

    let activeBanner = null;
    let bannerDismissTimer = null;

    function removeBanner() {
        if (bannerDismissTimer) { clearTimeout(bannerDismissTimer); bannerDismissTimer = null; }
        if (activeBanner && activeBanner.parentNode) activeBanner.parentNode.removeChild(activeBanner);
        activeBanner = null;
    }

    /**
     * Show an accessible inline warning banner.
     * @param {string} detectionName - Safe classification name (from PATTERNS array)
     * @param {Function} onAllow
     * @param {Function} onDeny
     */
    function showPasteWarningBanner(detectionName, onAllow, onDeny) {
        removeBanner();
        ensureStyles();

        // --- Build banner using safe DOM APIs (no innerHTML) ---
        const denyBtn = el('button', {
            className: 'ztbg-action-btn',
            style: 'padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;background:#ff4d4d;color:white;margin-right:8px;',
            textContent: '🚫 Cancel Paste',
        });

        const allowBtn = el('button', {
            className: 'ztbg-action-btn',
            style: 'padding:8px 16px;border-radius:8px;border:1px solid rgba(255,255,255,0.2);cursor:pointer;font-size:13px;font-weight:600;background:rgba(255,255,255,0.1);color:#e0e0e0;',
            textContent: 'Paste Anyway',
        });

        const closeBtn = el('button', {
            style: 'background:none;border:none;color:#666;cursor:pointer;font-size:18px;padding:0;line-height:1;',
            textContent: '×',
        });

        const label = el('div', {
            style: 'font-weight:700;color:#ff4d4d;margin-bottom:6px;',
            textContent: '⚠️ ZTBG: Sensitive Data Detected',
        });

        const nameSpan = el('span', { style: 'color:#00d4ff;font-weight:600;' });
        nameSpan.textContent = detectionName; // Safe: textContent assignment

        const desc = el('div', { style: 'margin-bottom:12px;color:#b0b0b0;line-height:1.5;' }, [
            'A possible ',
            nameSpan,
            ' was detected in your clipboard. Are you sure you want to paste this here?',
        ]);

        const btnRow = el('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;' }, [denyBtn, allowBtn]);
        const textCol = el('div', { style: 'flex:1;' }, [label, desc, btnRow]);
        const icon = el('span', { style: 'font-size:24px;flex-shrink:0;', textContent: '🛡️' });
        const row = el('div', { style: 'display:flex;align-items:flex-start;gap:12px;' }, [icon, textCol, closeBtn]);

        const banner = el('div', {
            id: 'ztbg-paste-warning',
            role: 'alertdialog',
            'aria-live': 'assertive',
            style: [
                'position:fixed;top:16px;left:50%;transform:translateX(-50%);',
                'z-index:2147483647;',
                'background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);',
                'border:1px solid #ff4d4d;border-radius:12px;padding:16px 20px;',
                'max-width:520px;width:calc(100% - 32px);',
                'box-shadow:0 8px 32px rgba(255,77,77,0.3);',
                "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;",
                'font-size:14px;color:#e0e0e0;',
                'animation:ztbgSlideDown 0.3s cubic-bezier(0.34,1.56,0.64,1);',
            ].join(''),
        }, [row]);

        document.body.appendChild(banner);
        activeBanner = banner;

        denyBtn.addEventListener('click', () => { removeBanner(); onDeny(); }, { once: true });
        allowBtn.addEventListener('click', () => { removeBanner(); onAllow(); }, { once: true });
        closeBtn.addEventListener('click', () => { removeBanner(); onDeny(); }, { once: true });

        bannerDismissTimer = setTimeout(removeBanner, 15000);
    }

    // ─── Form Submit Modal (XSS-safe DOM construction) ───────────────────────

    let activeModal = null;
    let activeOverlay = null;

    function removeModal() {
        if (activeModal && activeModal.parentNode) activeModal.parentNode.removeChild(activeModal);
        if (activeOverlay && activeOverlay.parentNode) activeOverlay.parentNode.removeChild(activeOverlay);
        activeModal = activeOverlay = null;
        document.removeEventListener('keydown', modalKeyHandler);
    }

    function modalKeyHandler(e) {
        if (e.key === 'Escape') { removeModal(); }
    }

    /**
     * Show a blocking modal before form submission.
     * @param {Array<{name: string, severity: string}>} detections
     * @param {Function} onSend
     * @param {Function} onCancel
     */
    function showFormSubmitModal(detections, onSend, onCancel) {
        removeModal();
        ensureStyles();

        const overlay = el('div', {
            id: 'ztbg-modal-overlay',
            style: 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:2147483646;backdrop-filter:blur(4px);',
        });

        // Build detection list safely
        const listItems = detections.slice(0, 8).map(d => {
            const icon = d.severity === 'critical' ? '🔴' : '🟡';
            return el('li', {
                style: `padding:6px 0;color:${d.severity === 'critical' ? '#ff4d4d' : '#ffab00'};`,
            }, [`${icon} `, el('strong', { textContent: d.name })]);
        });

        const list = el('ul', { style: 'list-style:none;padding:12px 16px;margin:0 0 20px;background:rgba(255,255,255,0.04);border-radius:8px;' }, listItems);
        const titleIcon = el('div', { style: 'font-size:48px;margin-bottom:12px;', textContent: '🚨' });
        const titleText = el('h2', { style: 'color:#ff4d4d;font-size:18px;margin:0 0 8px;', textContent: 'Sensitive Data Detected' });
        const subtitle = el('p', { style: 'color:#888;font-size:14px;margin:0;', textContent: 'ZTBG detected the following in your form submission:' });
        const header = el('div', { style: 'text-align:center;margin-bottom:20px;' }, [titleIcon, titleText, subtitle]);

        const notice = el('p', {
            style: 'color:#888;font-size:13px;margin:0 0 20px;line-height:1.5;',
            textContent: 'Submitting may send sensitive credentials to this server. ZTBG has blocked this submission.',
        });

        const cancelBtn = el('button', {
            id: 'ztbg-modal-cancel',
            style: 'flex:1;padding:12px;border-radius:10px;border:none;background:#ff4d4d;color:white;font-weight:700;font-size:14px;cursor:pointer;',
            textContent: '🚫 Cancel Submission',
        });
        const sendBtn = el('button', {
            id: 'ztbg-modal-send',
            style: 'flex:1;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,0.15);background:rgba(255,255,255,0.06);color:#888;font-size:14px;cursor:pointer;',
            textContent: 'Send Anyway',
        });
        const btnRow = el('div', { style: 'display:flex;gap:12px;' }, [cancelBtn, sendBtn]);

        const modal = el('div', {
            id: 'ztbg-form-modal',
            role: 'alertdialog',
            'aria-modal': 'true',
            style: [
                'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);',
                'z-index:2147483647;',
                'background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);',
                'border:1px solid #ff4d4d;border-radius:16px;padding:28px;',
                'max-width:480px;width:calc(100% - 48px);',
                'box-shadow:0 20px 60px rgba(255,77,77,0.25);',
                "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;",
                'color:#e0e0e0;',
                'animation:ztbgModalIn 0.3s cubic-bezier(0.34,1.56,0.64,1);',
            ].join(''),
        }, [header, list, notice, btnRow]);

        document.body.appendChild(overlay);
        document.body.appendChild(modal);
        activeModal = modal;
        activeOverlay = overlay;

        cancelBtn.addEventListener('click', () => { removeModal(); onCancel(); }, { once: true });
        sendBtn.addEventListener('click', () => { removeModal(); onSend(); }, { once: true });
        overlay.addEventListener('click', () => { removeModal(); onCancel(); }, { once: true });
        document.addEventListener('keydown', modalKeyHandler);
    }

    // ─── Event Listeners ──────────────────────────────────────────────────────

    let pasteListenerAdded = false;
    let submitListenerAdded = false;
    let pasteEnabled = true;
    let submitEnabled = true;

    /**
     * Initialise clipboard paste monitoring (registers listener once).
     */
    function initPasteMonitoring() {
        if (pasteListenerAdded) return;
        pasteListenerAdded = true;

        document.addEventListener('paste', (event) => {
            if (!pasteEnabled) return;

            const target = event.target;
            if (!target) return;

            const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;
            if (!isInput) return;

            const clipboardText = event.clipboardData ? event.clipboardData.getData('text') : '';
            if (!clipboardText) return;

            const detections = scanForSensitiveData(clipboardText);
            if (detections.length === 0) return;

            // Block the paste — ask user
            event.preventDefault();
            event.stopPropagation();

            const detectionName = detections[0].name;
            // Save the clipboard text in closure for the "allow" path only
            const savedText = clipboardText;

            showPasteWarningBanner(
                detectionName,
                () => {
                    // User chose to paste anyway — insert text manually
                    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
                        const start = target.selectionStart || 0;
                        const end = target.selectionEnd || 0;
                        target.value = target.value.substring(0, start) + savedText + target.value.substring(end);
                        target.selectionStart = target.selectionEnd = start + savedText.length;
                        target.dispatchEvent(new Event('input', { bubbles: true }));
                    } else if (target.isContentEditable) {
                        document.execCommand('insertText', false, savedText);
                    }
                    // Log metadata only (not the secret)
                    safelySendMessage({
                        type: 'ZTBG_THREAT_LOG',
                        payload: { event: 'paste_allowed', detections, url: location.href, timestamp: Date.now() },
                    });
                },
                () => {
                    safelySendMessage({
                        type: 'ZTBG_THREAT_LOG',
                        payload: { event: 'paste_blocked', detections, url: location.href, timestamp: Date.now() },
                    });
                }
            );
        }, true); // Capture phase
    }

    /**
     * Initialise form submit monitoring (registers listener once).
     */
    function initFormSubmitMonitoring() {
        if (submitListenerAdded) return;
        submitListenerAdded = true;

        document.addEventListener('submit', (event) => {
            if (!submitEnabled) return;

            const form = event.target;
            if (!form || !(form instanceof HTMLFormElement)) return;

            const allDetections = [];
            form.querySelectorAll('input, textarea').forEach((input) => {
                const value = (input.value || '').trim();
                if (!value) return;
                allDetections.push(...scanForSensitiveData(value));
            });

            if (allDetections.length === 0) return;

            event.preventDefault();
            event.stopPropagation();

            showFormSubmitModal(
                allDetections,
                () => {
                    submitEnabled = false;
                    try { form.submit(); } catch (_) { }
                    setTimeout(() => { submitEnabled = true; }, 500);

                    safelySendMessage({
                        type: 'ZTBG_THREAT_LOG',
                        payload: { event: 'form_submit_allowed', detections: allDetections, url: location.href, timestamp: Date.now() },
                    });
                },
                () => {
                    safelySendMessage({
                        type: 'ZTBG_THREAT_LOG',
                        payload: { event: 'form_submit_blocked', detections: allDetections, url: location.href, timestamp: Date.now() },
                    });
                }
            );
        }, true);
    }

    // ─── Safe messaging helper ────────────────────────────────────────────────

    function safelySendMessage(msg) {
        try {
            chrome.runtime.sendMessage(msg).catch(() => { });
        } catch (_) { }
    }

    // ─── Public Init ──────────────────────────────────────────────────────────

    /**
     * Initialise data-leak protection. Safe to call multiple times — idempotent.
     * @param {{ alertOnPaste?: boolean, alertOnSubmit?: boolean }} settings
     */
    function init(settings = {}) {
        if (settings.alertOnPaste !== false) initPasteMonitoring();
        if (settings.alertOnSubmit !== false) initFormSubmitMonitoring();
    }

    // Export
    global.ZTBGDataLeak = {
        init,
        scanForSensitiveData,
        luhnCheck,
    };

})(typeof globalThis !== 'undefined' ? globalThis : self);
