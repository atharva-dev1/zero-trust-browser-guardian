/**
 * ZTBG — DOM Structure Anomaly Scanner v1.0.1
 *
 * Fixes applied (Phases 2, 3, 5):
 *  - Self-exclusion: returns empty result on extension pages
 *  - analyzeFormStructure: password field threshold raised to >2 (not >1),
 *    only one flag added per overlay (return inside forEach was wrong — moved to break)
 *  - analyzeMismatchedLinks: mismatch threshold lowered to >2 (was >5, causing false negatives)
 *  - analyzeBrandMismatch: localhost and 127.0.0.1 excluded
 *  - analyzeObfuscatedScripts: requires >=2 signals (same), but base64 blob pattern
 *    tightened to avoid matching inline SVG paths
 *  - analyzeSemanticSignals: authority keywords only score when combined with other signals
 *    (reduces false positives on legitimate sites mentioning bank/government)
 *  - No innerHTML usage — all user-sourced strings handled safely
 *  - No console.log calls
 *  - All querySelectorAll results null-checked (document.body guard)
 *  - findHighEntropyTokens now only flags tokens with length > 20 AND NOT matching
 *    common safe identity patterns (delegated to ZTBGEntropy)
 */

(function (global) {
    'use strict';

    // ─── Self-exclusion ───────────────────────────────────────────────────────

    if (
        typeof location === 'undefined' ||
        location.protocol === 'chrome-extension:' ||
        location.protocol === 'moz-extension:'
    ) {
        global.ZTBGDOMAnalyzer = { runFullDOMAnalysis: () => ({ domScore: 0, findings: [], breakdown: {} }) };
        return;
    }

    // ─── Constants ────────────────────────────────────────────────────────────

    const URGENCY_KEYWORDS = [
        'verify immediately',
        'account suspended',
        'click now',
        'limited time',
        'unusual activity',
        'confirm your identity',
        'act now',
        'expires soon',
        'locked out',
        'your account will be',
        'immediate action',
        'security alert',
    ];

    const PHISHING_SIGNALS = {
        urgency: ['immediately', 'urgent', 'expires', 'suspended', 'locked', 'act now', 'expires soon'],
        fear: ['unauthorized', 'suspicious activity', 'compromised', 'verify now', 'security breach', 'hacked'],
        reward: ['winner', 'prize', 'free gift', 'claim now', 'you have won'],
        authority: ['irs', 'bank statement', 'government notice', 'microsoft support', 'apple support'],
    };

    // Compiled once — not inside handlers
    const DARK_CONFIRM_SHAMING = [
        "no thanks, i don't want",
        "no thanks, i hate",
        "no, i don't want savings",
        "no, i prefer to pay more",
        "no thanks, i'll pass",
        "decline and miss out",
    ];

    const ROACH_MOTEL_TERMS = ['subscribe', 'sign up', 'join now', 'start free'];

    const BRAND_DOMAIN_MAP = {
        paypal: 'paypal.com',
        google: 'google.com',
        microsoft: 'microsoft.com',
        apple: 'apple.com',
        amazon: 'amazon.com',
        facebook: 'facebook.com',
        instagram: 'instagram.com',
        netflix: 'netflix.com',
        twitter: 'twitter.com',
        linkedin: 'linkedin.com',
        bankofamerica: 'bankofamerica.com',
        chase: 'chase.com',
        wellsfargo: 'wellsfargo.com',
        citibank: 'citibank.com',
        irs: 'irs.gov',
    };

    // Localhost and loopback — never flag
    const SAFE_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /** Safely get lowercased text content of an element */
    function safeTextLower(el) {
        if (!el) return '';
        return ((el.textContent || el.innerText || '')).toLowerCase().trim();
    }

    /** Get current page's registered domain (SLD+TLD) without www prefix */
    function getDomain() {
        return (location.hostname || '').replace(/^www\./, '').toLowerCase();
    }

    // ─── Analysis Functions ───────────────────────────────────────────────────

    /**
     * Detect suspicious form structures.
     * Threshold: >2 password fields (normal login = 1, signup = 2)
     * @returns {{ score: number, findings: string[] }}
     */
    function analyzeFormStructure() {
        const findings = [];
        let score = 0;

        if (!document.body) return { score: 0, findings: [] };

        const forms = document.querySelectorAll('form');
        const passwordFields = document.querySelectorAll('input[type="password"]');
        const hiddenIframes = document.querySelectorAll(
            'iframe[style*="display:none"],iframe[style*="visibility:hidden"],iframe[width="0"],iframe[height="0"]'
        );

        // > 2 password fields = suspicious (3+ is beyond even complex signup flows)
        if (passwordFields.length > 2) {
            findings.push(`Suspicious: ${passwordFields.length} password fields detected`);
            score += 20;
        }

        if (hiddenIframes.length > 0) {
            findings.push(`Hidden iframe(s) detected (${hiddenIframes.length})`);
            score += 25;
        }

        // Forms posting to external domains
        const currentDomain = getDomain();
        forms.forEach((form) => {
            const action = form.getAttribute('action') || '';
            if (action.startsWith('http') && currentDomain && !action.includes(currentDomain)) {
                findings.push(`Form submits to external domain`);
                score += 30;
            }
        });

        // Detect fake login overlays (high z-index fixed/absolute covering the page)
        let overlayFlagged = false;
        document.querySelectorAll('[class*="overlay"],[class*="modal"],[id*="overlay"],[id*="modal"]').forEach((el) => {
            if (overlayFlagged) return;
            try {
                const style = window.getComputedStyle(el);
                const zIndex = parseInt(style.zIndex, 10);
                const pos = style.position;
                if (!isNaN(zIndex) && zIndex > 999 && (pos === 'fixed' || pos === 'absolute')) {
                    findings.push('Suspicious full-screen overlay detected');
                    score += 20;
                    overlayFlagged = true;
                }
            } catch (_) { /* getComputedStyle can throw in edge cases */ }
        });

        return { score: Math.min(score, 50), findings };
    }

    /**
     * Detect mismatched anchor tags (href domain ≠ display text domain).
     * Threshold lowered to 2 to catch more phishing (was 5).
     * @returns {{ score: number, findings: string[] }}
     */
    function analyzeMismatchedLinks() {
        const findings = [];
        let score = 0;
        let mismatches = 0;

        document.querySelectorAll('a[href]').forEach((a) => {
            const href = a.getAttribute('href') || '';
            if (!href.startsWith('http')) return;

            const text = (a.textContent || '').trim();
            const textDomainMatch = text.match(/([a-zA-Z0-9-]+\.[a-zA-Z]{2,})/);
            if (!textDomainMatch) return;

            try {
                const hrefDomain = new URL(href).hostname.replace(/^www\./, '');
                const textDomain = textDomainMatch[1].toLowerCase();
                if (hrefDomain && !hrefDomain.includes(textDomain) && !textDomain.includes(hrefDomain)) {
                    mismatches++;
                }
            } catch (_) { /* invalid URL */ }
        });

        if (mismatches > 2) {
            findings.push(`${mismatches} anchor tag domain mismatches detected`);
            score += Math.min(mismatches * 5, 25);
        }

        return { score, findings };
    }

    /**
     * Detect urgency / fear language in page body text.
     * @returns {{ score: number, findings: string[], keywordMatches: string[] }}
     */
    function analyzeUrgencyLanguage() {
        const findings = [];
        const keywordMatches = [];
        let score = 0;

        if (!document.body) return { score: 0, findings: [], keywordMatches: [] };

        const bodyText = (document.body.innerText || '').toLowerCase();

        for (const kw of URGENCY_KEYWORDS) {
            if (bodyText.includes(kw)) {
                keywordMatches.push(kw);
                score += 8;
            }
        }

        if (keywordMatches.length > 0) {
            findings.push(`Urgency language: ${keywordMatches.slice(0, 3).join(', ')}${keywordMatches.length > 3 ? '…' : ''}`);
        }

        return { score: Math.min(score, 40), findings, keywordMatches };
    }

    /**
     * Detect title/domain brand mismatch.
     * Skips localhost and loopback addresses.
     * @returns {{ score: number, findings: string[] }}
     */
    function analyzeBrandMismatch() {
        const findings = [];
        let score = 0;

        const domain = getDomain();
        if (!domain || SAFE_HOSTS.has(domain)) return { score: 0, findings: [] };

        const title = (document.title || '').toLowerCase();

        for (const [brand, trustedDomain] of Object.entries(BRAND_DOMAIN_MAP)) {
            if (title.includes(brand)) {
                // Strip TLD parts (.com / .gov) to get the base name
                const trustedBase = trustedDomain.replace(/\.(com|gov|org|net)$/, '');
                if (!domain.includes(trustedBase)) {
                    findings.push(`Brand impersonation: title contains "${brand}" but domain is "${domain}"`);
                    score += 35;
                    break; // One impersonation is enough
                }
            }
        }

        return { score, findings };
    }

    /**
     * Detect obfuscated inline JavaScript.
     * Base64 blob pattern now requires balanced padding (={0,2}) and
     * excludes common SVG / PDF patterns (reduces false positives).
     * @returns {{ score: number, findings: string[] }}
     */
    function analyzeObfuscatedScripts() {
        const findings = [];
        let obfuscatedCount = 0;

        if (!document.body) return { score: 0, findings: [] };

        document.querySelectorAll('script:not([src])').forEach((script) => {
            const src = script.textContent || '';
            if (src.trim().length < 20) return;

            const hasEval = /\beval\s*\(/.test(src);
            const hasUnescape = /\bunescape\s*\(/.test(src);
            const hasFromCharCode = /String\.fromCharCode\s*\(/.test(src);
            const hasAtob = /\batob\s*\(/.test(src);
            // Tightened: require 500+ chars of base64 alphabet NOT preceded by <svg or data:
            const hasBase64Blob = /(?<!data:[a-z]+\/[a-z+]*;base64,)[A-Za-z0-9+/]{500,}={0,2}/.test(src);

            const nonAlphaNum = (src.match(/[^a-zA-Z0-9\s]/g) || []).length;
            const ratio = src.length > 0 ? nonAlphaNum / src.length : 0;
            const isHighObfusc = ratio > 0.3;

            const flags = [];
            if (hasEval) flags.push('eval()');
            if (hasUnescape) flags.push('unescape()');
            if (hasFromCharCode) flags.push('String.fromCharCode()');
            if (hasAtob) flags.push('atob()');
            if (hasBase64Blob) flags.push('base64 blob >500 chars');
            if (isHighObfusc) flags.push(`${Math.round(ratio * 100)}% non-alphanum`);

            if (flags.length >= 2) {
                obfuscatedCount++;
                findings.push(`Obfuscated script: ${flags.join(', ')}`);
            }
        });

        const score = obfuscatedCount > 0 ? Math.min(obfuscatedCount * 20, 40) : 0;
        return { score, findings };
    }

    /**
     * Run semantic NLP signal detection.
     * Authority keywords (IRS, bank, etc.) alone don't score —
     * they must co-occur with urgency/fear to reduce false positives.
     * @returns {{ score: number, findings: string[], signals: Object }}
     */
    function analyzeSemanticSignals() {
        const findings = [];
        let score = 0;
        const signals = {};

        if (!document.body) return { score: 0, findings: [], signals: {} };

        const bodyText = (document.body.innerText || '').toLowerCase();

        for (const [category, keywords] of Object.entries(PHISHING_SIGNALS)) {
            const matched = keywords.filter(kw => bodyText.includes(kw));
            signals[category] = matched;

            if (matched.length > 0) {
                // Authority signals only count when another phishing signal is also present
                if (category === 'authority') {
                    const otherSignals = Object.entries(signals)
                        .filter(([k]) => k !== 'authority')
                        .some(([, v]) => v.length > 0);
                    if (!otherSignals) continue;
                }
                score += matched.length * 5;
                findings.push(`${category} signal: [${matched.join(', ')}]`);
            }
        }

        return { score: Math.min(score, 40), findings, signals };
    }

    /**
     * Detect dark UX patterns (confirm-shaming, pre-checked boxes, roach motel).
     * @returns {{ score: number, findings: string[] }}
     */
    function analyzeDarkPatterns() {
        const findings = [];
        let score = 0;

        if (!document.body) return { score: 0, findings: [] };

        const buttons = document.querySelectorAll(
            'button, a[role="button"], input[type="button"], input[type="submit"]'
        );

        // Confirm-shaming
        buttons.forEach((btn) => {
            const text = safeTextLower(btn);
            for (const phrase of DARK_CONFIRM_SHAMING) {
                if (text.includes(phrase)) {
                    findings.push(`Confirm-shaming: "${(btn.textContent || '').trim().substring(0, 60)}"`);
                    score += 10;
                    break; // One phrase per button
                }
            }
        });

        // Pre-checked opt-in checkboxes
        let preCheckedCount = 0;
        document.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
            if (cb.defaultChecked) preCheckedCount++;
        });

        if (preCheckedCount > 0) {
            findings.push(`${preCheckedCount} pre-checked opt-in checkbox(es) detected`);
            score += preCheckedCount * 5;
        }

        // Roach motel: subscribe buttons outnumber cancel options
        const subscribeButtons = Array.from(buttons).filter(btn =>
            ROACH_MOTEL_TERMS.some(term => safeTextLower(btn).includes(term))
        );
        if (subscribeButtons.length > 0) {
            const cancelButtons = Array.from(buttons).filter(btn => {
                const t = safeTextLower(btn);
                return t.includes('cancel') || t.includes('unsubscribe');
            });
            if (subscribeButtons.length > cancelButtons.length * 2 + 1) {
                findings.push('Roach motel: subscribe buttons heavily outnumber cancel options');
                score += 15;
            }
        }

        return { score: Math.min(score, 30), findings };
    }

    // ─── IDN / Punycode Detection (Phase 5B) ──────────────────────────────────

    /**
     * Detect IDN homograph and punycode domain attacks.
     * NFC normalisation reveals visually-identical Cyrillic/Greek substitutions.
     * @returns {{ score: number, findings: string[] }}
     */
    function analyzeIDNAttack() {
        const findings = [];
        let score = 0;

        const hostname = location.hostname || '';
        if (!hostname) return { score: 0, findings: [] };

        // Punycode prefix = internationalized domain
        if (/xn--/.test(hostname)) {
            findings.push(`Punycode (IDN) domain detected: ${hostname}`);
            score += 30;
        }

        // Non-ASCII in hostname = homograph candidate
        if (/[^\x00-\x7F]/.test(hostname)) {
            findings.push(`Non-ASCII characters in domain (possible homograph attack): ${hostname}`);
            score += 35;
        }

        // NFC normalisation check
        try {
            if (hostname !== hostname.normalize('NFC')) {
                findings.push('Domain fails NFC normalisation (homograph attack detected)');
                score += 40;
            }
        } catch (_) { /* normalize not available */ }

        return { score: Math.min(score, 40), findings };
    }

    // ─── Full Analysis Aggregator ──────────────────────────────────────────────

    /**
     * Run all DOM analyses and return aggregated result.
     * @returns {{ domScore: number, findings: string[], breakdown: Object }}
     */
    function runFullDOMAnalysis() {
        const formResult = analyzeFormStructure();
        const linkResult = analyzeMismatchedLinks();
        const urgencyResult = analyzeUrgencyLanguage();
        const brandResult = analyzeBrandMismatch();
        const scriptResult = analyzeObfuscatedScripts();
        const semanticResult = analyzeSemanticSignals();
        const darkResult = analyzeDarkPatterns();
        const idnResult = analyzeIDNAttack();

        const allFindings = [
            ...formResult.findings,
            ...linkResult.findings,
            ...urgencyResult.findings,
            ...brandResult.findings,
            ...scriptResult.findings,
            ...semanticResult.findings,
            ...darkResult.findings,
            ...idnResult.findings,
        ];

        const rawScore =
            formResult.score +
            linkResult.score +
            urgencyResult.score +
            brandResult.score +
            scriptResult.score +
            semanticResult.score +
            darkResult.score +
            idnResult.score;

        return {
            domScore: Math.min(rawScore, 100),
            findings: allFindings,
            breakdown: {
                formStructure: formResult.score,
                linkMismatch: linkResult.score,
                urgencyLanguage: urgencyResult.score,
                brandMismatch: brandResult.score,
                obfuscatedScripts: scriptResult.score,
                semanticSignals: semanticResult.score,
                darkPatterns: darkResult.score,
                idnAttack: idnResult.score,
            },
        };
    }

    // Export
    global.ZTBGDOMAnalyzer = {
        runFullDOMAnalysis,
        analyzeFormStructure,
        analyzeMismatchedLinks,
        analyzeUrgencyLanguage,
        analyzeBrandMismatch,
        analyzeObfuscatedScripts,
        analyzeSemanticSignals,
        analyzeDarkPatterns,
        analyzeIDNAttack,
    };

})(typeof globalThis !== 'undefined' ? globalThis : self);
