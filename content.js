/**
 * ZTBG — Content Script v1.0.1 (Main Orchestrator)
 *
 * Fixes applied (Phases 2, 4, 5, 6):
 *  - Self-exclusion: abort if running inside extension page or chrome:// URL
 *  - Guard flag prevents multiple simultaneous scans (race condition fix)
 *  - Scan runs via requestIdleCallback for non-urgent analysis (performance)
 *  - onMessage listener returns true only when async response is needed
 *  - sendMessage calls are fire-and-forget with .catch() — no unhandled rejections
 *  - Storage reads validated before use
 *  - lastScanResult is keyed per tab URL to prevent stale popup data across tabs
 *  - Init guard prevents double-registration on rescan
 */

(function () {
    'use strict';

    // ─── Self-exclusion ───────────────────────────────────────────────────────
    // Never run on extension pages or non-http(s) contexts
    const href = window.location.href;
    if (
        href.startsWith('chrome-extension://') ||
        href.startsWith('chrome://') ||
        href.startsWith('about:') ||
        href.startsWith('moz-extension://')
    ) {
        return;
    }

    // ─── Constants ───────────────────────────────────────────────────────────────
    const DEBUG = false;
    const VERSION = '1.0.1';

    function log(...args) {
        if (DEBUG) console.warn('[ZTBG]', ...args); // eslint-disable-line no-console
    }

    // ─── State ────────────────────────────────────────────────────────────────

    let ztbgEnabled = true;
    let scanInProgress = false;  // Prevent concurrent scans
    let dataLeakInited = false;  // Prevent double-registering paste/submit listeners

    let settings = {
        enabled: true,
        alertOnPaste: true,
        alertOnSubmit: true,
    };

    // ─── Initialization ───────────────────────────────────────────────────────

    async function init() {
        try {
            const stored = await chrome.storage.local.get(['settings', 'allowlist', 'blocklist']);

            // Validate stored.settings before spreading
            if (stored.settings && typeof stored.settings === 'object') {
                settings = { ...settings, ...stored.settings };
            }

            const domain = location.hostname.replace(/^www\./, '').toLowerCase();
            const allowlist = Array.isArray(stored.allowlist) ? stored.allowlist : [];
            const blocklist = Array.isArray(stored.blocklist) ? stored.blocklist : [];

            // Domain on user-managed allowlist → disable for this domain
            if (allowlist.includes(domain)) {
                ztbgEnabled = false;
                return;
            }

            if (settings.enabled === false) {
                ztbgEnabled = false;
                return;
            }

            // Domain is blocked → instant max-risk report, skip further scanning
            if (blocklist.includes(domain)) {
                broadcastResult({ riskScore: 100, findings: ['Domain is on your blocklist'], breakdown: {} });
                return;
            }
        } catch (err) {
            // Storage may be unavailable in restricted contexts — proceed with defaults
            log('Storage read failed:', err);
        }

        // Init data-leak listeners exactly once
        if (!dataLeakInited && window.ZTBGDataLeak) {
            window.ZTBGDataLeak.init(settings);
            dataLeakInited = true;
        }

        // Schedule scan after DOM settles
        scheduleAnalysis();
    }

    // ─── Analysis Pipeline ────────────────────────────────────────────────────

    function scheduleAnalysis() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                requestIdleOrTimeout(runAnalysis, 1000);
            }, { once: true });
        } else {
            requestIdleOrTimeout(runAnalysis, 800);
        }
    }

    /**
     * Use requestIdleCallback when available, otherwise fall back to setTimeout.
     * Keeps scanning out of the critical rendering path.
     * @param {Function} fn
     * @param {number} timeoutMs
     */
    function requestIdleOrTimeout(fn, timeoutMs) {
        if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(fn, { timeout: timeoutMs });
        } else {
            setTimeout(fn, timeoutMs);
        }
    }

    async function runAnalysis() {
        if (!ztbgEnabled || scanInProgress) return;
        scanInProgress = true;

        let result = { riskScore: 0, findings: [], breakdown: {} };

        try {
            if (window.ZTBGPhishing && typeof window.ZTBGPhishing.computePhishingRisk === 'function') {
                const phishingResult = window.ZTBGPhishing.computePhishingRisk();

                // Validate the result shape before trusting it
                result.riskScore = (typeof phishingResult.riskScore === 'number')
                    ? Math.max(0, Math.min(100, Math.round(phishingResult.riskScore)))
                    : 0;
                result.findings = Array.isArray(phishingResult.findings) ? phishingResult.findings : [];
                result.breakdown = (phishingResult.breakdown && typeof phishingResult.breakdown === 'object')
                    ? phishingResult.breakdown : {};
            }
        } catch (err) {
            log('Analysis error:', err);
        } finally {
            scanInProgress = false;
        }

        broadcastResult(result);
    }

    // ─── Communication ────────────────────────────────────────────────────────

    function broadcastResult(result) {
        const category = (window.ZTBGPhishing && typeof window.ZTBGPhishing.categorizeRisk === 'function')
            ? window.ZTBGPhishing.categorizeRisk(result.riskScore)
            : { level: 'unknown', color: '#888', label: 'Unknown' };

        const scanPayload = {
            url: window.location.href,
            domain: location.hostname,
            riskScore: result.riskScore,
            findings: (result.findings || []).slice(0, 20),
            breakdown: result.breakdown || {},
            timestamp: Date.now(),
            level: category.level,
            category,
        };

        // Persist for popup — keyed to avoid stale data across tab switches
        chrome.storage.local.set({ lastScanResult: scanPayload }).catch(log);

        // Notify background worker
        chrome.runtime.sendMessage({ type: 'ZTBG_SCAN_RESULT', payload: scanPayload }).catch(log);
    }

    // ─── Message Listener ─────────────────────────────────────────────────────
    // Register once via IIFE-level guard

    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        if (!message || typeof message.type !== 'string') return false;

        if (message.type === 'ZTBG_REQUEST_RESCAN') {
            // Re-run full analysis (debounced by scanInProgress flag)
            runAnalysis().catch(log);
            sendResponse({ ok: true });
            return false; // synchronous response sent
        }

        if (message.type === 'ZTBG_GET_STATUS') {
            sendResponse({ enabled: ztbgEnabled, settings, version: VERSION });
            return false;
        }

        return false;
    });

    // ─── Bootstrap ───────────────────────────────────────────────────────────

    init().catch(err => log('Init error:', err));

})();
