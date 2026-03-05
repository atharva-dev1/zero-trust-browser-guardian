/**
 * ZTBG — Background Service Worker v1.0.1
 *
 * Fixes applied (Phases 2, 3, 4, 6):
 *  - Message validation: rejects malformed/untrusted messages
 *  - onInstalled uses chrome.storage.local.get first to avoid wiping user data on update
 *  - Removed all console.log (replaced with ZTBG_LOG utility, off in production)
 *  - handleScanResult validates payload fields before use
 *  - handleThreatLog: stores only metadata, never raw secret values
 *  - appendSessionLog: uses chrome.storage.local (MV3-safe, no in-memory state)
 *  - All async handlers wrapped in try/catch
 *  - Message sender validated (must be extension itself or content script on http(s))
 *  - chrome.runtime.onMessage returns true only on async branches
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

const VERSION = '1.0.1';
const MAX_SESSION_LOGS = 50;
const DEBUG = false; // Set true only during local development

const BADGE_COLORS = {
    safe: '#00e676',
    suspicious: '#ffab00',
    dangerous: '#ff4d4d',
    unknown: '#555555',
};

const VALID_MESSAGE_TYPES = new Set([
    'ZTBG_SCAN_RESULT',
    'ZTBG_THREAT_LOG',
    'ZTBG_TOGGLE_DOMAIN',
    'ZTBG_GET_SESSION_LOG',
    'ZTBG_GET_STATS',
]);

// ─── Logger ───────────────────────────────────────────────────────────────────

function log(...args) {
    if (DEBUG) console.log('[ZTBG BG]', ...args);  // eslint-disable-line no-console
}

// ─── Initialization ───────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async (details) => {
    try {
        // Only set defaults that are not already present (preserves user data on update)
        const existing = await chrome.storage.local.get(['settings', 'allowlist', 'blocklist', 'sessionLog', 'stats']);

        const defaults = {
            settings: existing.settings || { enabled: true, alertOnPaste: true, alertOnSubmit: true },
            allowlist: existing.allowlist || [],
            blocklist: existing.blocklist || [],
            sessionLog: existing.sessionLog || [],
            stats: existing.stats || { threatsBlockedTotal: 0, scansTotal: 0 },
        };

        await chrome.storage.local.set(defaults);
        log('Storage initialized. Reason:', details.reason);
    } catch (err) {
        log('Storage init failed:', err);
    }
});

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // ── Security: validate message structure ──────────────────────────────────
    if (!message || typeof message.type !== 'string') return false;
    if (!VALID_MESSAGE_TYPES.has(message.type)) return false;

    // ── Security: only trust messages from our own extension or http(s) content scripts
    const isOwnExtension = sender.id === chrome.runtime.id;
    const isContentScript = sender.tab != null &&
        (sender.url?.startsWith('http://') || sender.url?.startsWith('https://'));

    if (!isOwnExtension && !isContentScript) return false;

    const { type, payload } = message;

    switch (type) {
        case 'ZTBG_SCAN_RESULT':
            handleScanResult(payload, sender.tab).catch(log);
            return false; // fire-and-forget, no response needed

        case 'ZTBG_THREAT_LOG':
            handleThreatLog(payload).catch(log);
            return false;

        case 'ZTBG_TOGGLE_DOMAIN':
            handleToggleDomain(payload, sendResponse);
            return true; // async response

        case 'ZTBG_GET_SESSION_LOG':
            getSessionLog().then(sendResponse).catch(() => sendResponse([]));
            return true;

        case 'ZTBG_GET_STATS':
            getStats().then(sendResponse).catch(() => sendResponse({}));
            return true;

        default:
            return false;
    }
});

// ─── Tab Update — Trigger Re-scan ─────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete') return;
    if (!tab.url) return;

    const url = tab.url;
    // Skip non-http(s) pages — content scripts don't run there
    if (!url.startsWith('http://') && !url.startsWith('https://')) return;

    // Immediately set "scanning" badge
    await setBadge(tabId, '…', BADGE_COLORS.unknown);

    // Ask the content script to rescan (it will reply via ZTBG_SCAN_RESULT)
    try {
        await chrome.tabs.sendMessage(tabId, { type: 'ZTBG_REQUEST_RESCAN' });
    } catch (_) {
        // Content script may not be injected yet on this frame — it reports on its own
    }
});

// ─── Handlers ─────────────────────────────────────────────────────────────────

/**
 * Handle incoming scan result from content script.
 * @param {Object} payload
 * @param {chrome.tabs.Tab} tab
 */
async function handleScanResult(payload, tab) {
    if (!tab || !tab.id) return;

    // Validate payload
    const riskScore = typeof payload?.riskScore === 'number'
        ? Math.max(0, Math.min(100, Math.round(payload.riskScore)))
        : 0;
    const findings = Array.isArray(payload?.findings) ? payload.findings.slice(0, 20) : [];
    const breakdown = (payload?.breakdown && typeof payload.breakdown === 'object') ? payload.breakdown : {};
    const url = typeof payload?.url === 'string' ? payload.url : '';

    const level = getRiskLevel(riskScore);
    await setBadge(tab.id, String(riskScore), BADGE_COLORS[level] || BADGE_COLORS.unknown);

    // Persist sanitised result for popup
    await chrome.storage.local.set({
        lastScanResult: {
            url,
            domain: typeof payload?.domain === 'string' ? payload.domain : '',
            riskScore,
            findings,
            breakdown,
            timestamp: Date.now(),
            level,
        },
    });

    await appendSessionLog({ url, riskScore, level, findings, timestamp: Date.now(), tabId: tab.id });
    await incrementScanCount();

    log(`Scan: ${url} → score=${riskScore} (${level})`);
}

/**
 * Handle threat log from data-leak module.
 * SECURITY: stores only metadata, NOT the actual secret values.
 */
async function handleThreatLog(payload) {
    if (!payload || typeof payload.event !== 'string') return;

    const { event, url, timestamp } = payload;

    // Strip actual secret content — store only detection names + severities
    const safeDetections = Array.isArray(payload.detections)
        ? payload.detections.map(d => ({ name: d.name, severity: d.severity }))
        : [];

    if (event === 'paste_blocked' || event === 'form_submit_blocked') {
        await incrementBlockedCount(safeDetections.length || 1);
    }

    await appendSessionLog({
        type: 'dataleak',
        event,
        detections: safeDetections,
        url: typeof url === 'string' ? url : '',
        timestamp: typeof timestamp === 'number' ? timestamp : Date.now(),
    });
}

/**
 * Toggle domain in allowlist / blocklist.
 * @param {{domain: string, action: string}} param0
 * @param {Function} sendResponse
 */
async function handleToggleDomain({ domain, action } = {}, sendResponse) {
    if (typeof domain !== 'string' || !domain) {
        sendResponse({ ok: false, error: 'Invalid domain' });
        return;
    }

    try {
        const stored = await chrome.storage.local.get(['allowlist', 'blocklist']);
        let allowlist = Array.isArray(stored.allowlist) ? stored.allowlist : [];
        let blocklist = Array.isArray(stored.blocklist) ? stored.blocklist : [];

        if (action === 'allow') {
            allowlist = [...new Set([...allowlist, domain])];
            blocklist = blocklist.filter(d => d !== domain);
        } else if (action === 'block') {
            blocklist = [...new Set([...blocklist, domain])];
            allowlist = allowlist.filter(d => d !== domain);
        } else if (action === 'remove') {
            allowlist = allowlist.filter(d => d !== domain);
            blocklist = blocklist.filter(d => d !== domain);
        }

        await chrome.storage.local.set({ allowlist, blocklist });
        sendResponse({ ok: true, allowlist, blocklist });
    } catch (err) {
        log('handleToggleDomain error:', err);
        sendResponse({ ok: false, error: String(err) });
    }
}

// ─── Badge Utilities ──────────────────────────────────────────────────────────

/**
 * Set the extension badge text and background colour for a tab.
 * @param {number} tabId
 * @param {string} text
 * @param {string} color  Hex colour string
 */
async function setBadge(tabId, text, color) {
    try {
        await chrome.action.setBadgeText({ tabId, text });
        await chrome.action.setBadgeBackgroundColor({ tabId, color });
    } catch (_) {
        // Tab may have been closed
    }
}

/**
 * Map 0–100 risk score to a named level.
 * @param {number} score
 * @returns {'safe'|'suspicious'|'dangerous'}
 */
function getRiskLevel(score) {
    if (score <= 30) return 'safe';
    if (score <= 60) return 'suspicious';
    return 'dangerous';
}

// ─── Session Log ──────────────────────────────────────────────────────────────

/**
 * Prepend an entry to the session log in chrome.storage.local.
 * MV3 note: service workers are ephemeral — all state MUST be in storage.
 * @param {Object} entry
 */
async function appendSessionLog(entry) {
    try {
        const stored = await chrome.storage.local.get('sessionLog');
        const log_ = Array.isArray(stored.sessionLog) ? stored.sessionLog : [];
        log_.unshift(entry);
        if (log_.length > MAX_SESSION_LOGS) log_.length = MAX_SESSION_LOGS;
        await chrome.storage.local.set({ sessionLog: log_ });
    } catch (err) {
        log('appendSessionLog error:', err);
    }
}

/**
 * Return the current session log.
 * @returns {Promise<Object[]>}
 */
async function getSessionLog() {
    const stored = await chrome.storage.local.get('sessionLog');
    return Array.isArray(stored.sessionLog) ? stored.sessionLog : [];
}

// ─── Stats ────────────────────────────────────────────────────────────────────

/**
 * Return the current stats object.
 * @returns {Promise<{threatsBlockedTotal: number, scansTotal: number}>}
 */
async function getStats() {
    const stored = await chrome.storage.local.get('stats');
    return (stored.stats && typeof stored.stats === 'object')
        ? stored.stats
        : { threatsBlockedTotal: 0, scansTotal: 0 };
}

async function incrementScanCount() {
    try {
        const stats = await getStats();
        await chrome.storage.local.set({ stats: { ...stats, scansTotal: (stats.scansTotal || 0) + 1 } });
    } catch (err) { log('incrementScanCount:', err); }
}

async function incrementBlockedCount(count = 1) {
    try {
        const stats = await getStats();
        await chrome.storage.local.set({ stats: { ...stats, threatsBlockedTotal: (stats.threatsBlockedTotal || 0) + count } });
    } catch (err) { log('incrementBlockedCount:', err); }
}
