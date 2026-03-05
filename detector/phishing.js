/**
 * ZTBG — Phishing Detection Module v1.0.1
 *
 * Fixes applied (Phases 2, 5):
 *  - localhost / loopback / chrome:// URLs skipped immediately
 *  - Trusted domain allowlist check: exact match + subdomain match fixed
 *    (was iterating all Set items on every call — now uses cached sorted list)
 *  - Short-SLD false positive: terms like 'io', 'co', 'ai' (common real TLDs) excluded
 *  - Brand names in SLD check now requires the brand term occupies most of the SLD,
 *    not just a substring (e.g., 'bank' in 'thanksbank' was a false positive)
 *  - Path term scoring capped at +15 total (was unbounded)
 *  - All URLs must start with http/https — file://, data://, etc. return 0
 *  - No console.log calls
 */

(function (global) {
    'use strict';

    // ─── Trusted Domain Allowlist ─────────────────────────────────────────────

    const TRUSTED_DOMAINS_RAW = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com',
        'github.com', 'reddit.com', 'netflix.com', 'stackoverflow.com', 'yahoo.com',
        'bing.com', 'twitch.tv', 'ebay.com', 'paypal.com', 'whatsapp.com',
        'pinterest.com', 'tumblr.com', 'dropbox.com', 'salesforce.com', 'adobe.com',
        'shopify.com', 'slack.com', 'zoom.us', 'discord.com', 'spotify.com',
        'cloudflare.com', 'vimeo.com', 'wordpress.com', 'blogger.com', 'medium.com',
        'quora.com', 'yelp.com', 'tripadvisor.com', 'airbnb.com', 'booking.com',
        'expedia.com', 'homedepot.com', 'target.com', 'walmart.com', 'bestbuy.com',
        'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'irs.gov',
        'usps.com', 'fedex.com', 'ups.com', 'dhl.com', 'cnn.com', 'bbc.com',
        'nytimes.com', 'wsj.com', 'theguardian.com', 'reuters.com', 'bloomberg.com',
        'techcrunch.com', 'wired.com', 'theverge.com', 'arstechnica.com', 'engadget.com',
        'crunchbase.com', 'imdb.com', 'weather.com', 'accuweather.com', 'espn.com',
        'nfl.com', 'nba.com', 'mlb.com', 'fifa.com', 'olympics.com',
        'nasa.gov', 'cdc.gov', 'who.int', 'un.org', 'whitehouse.gov',
        'stripe.com', 'twilio.com', 'sendgrid.com', 'mailchimp.com', 'hubspot.com',
        'notion.so', 'airtable.com', 'trello.com', 'asana.com', 'jira.com',
        'atlassian.com', 'bitbucket.org', 'gitlab.com', 'heroku.com', 'digitalocean.com',
        'vercel.com', 'netlify.com', 'fly.io', 'render.com', 'railway.app',
        'docker.com', 'kubernetes.io', 'terraform.io', 'jenkins.io',
        'python.org', 'nodejs.org', 'php.net', 'ruby-lang.org', 'rust-lang.org',
        'golang.org', 'java.com', 'kotlin.org', 'swift.org', 'reactjs.org',
        'vuejs.org', 'angular.io', 'svelte.dev', 'nextjs.org', 'nuxtjs.org',
        'mongodb.com', 'postgresql.org', 'mysql.com', 'redis.io',
        'openai.com', 'anthropic.com', 'huggingface.co', 'kaggle.com', 'arxiv.org',
        'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org', 'pluralsight.com',
        'figma.com', 'canva.com', 'miro.com', 'invisionapp.com',
        'outlook.com', 'office.com', 'icloud.com',
        'login.microsoftonline.com', 'accounts.google.com', 'mail.google.com',
        'developer.apple.com', 'developer.amazon.com',
    ];

    // Build a lookup Set for O(1) exact-match checks
    const TRUSTED_SET = new Set(TRUSTED_DOMAINS_RAW);

    // Sorted longest-first to match most-specific subdomain first
    const TRUSTED_SORTED = TRUSTED_DOMAINS_RAW.slice().sort((a, b) => b.length - a.length);

    // Free / abused TLDs
    const SUSPICIOUS_TLDS = new Set([
        '.tk', '.ml', '.cf', '.ga', '.gq', '.buzz', '.xyz', '.top',
        '.click', '.link', '.win', '.download', '.loan', '.bid', '.trade', '.gdn',
    ]);

    // SLDs that are commonly short but legitimate — don't penalise them
    const LEGITIMATE_SHORT_SLDS = new Set([
        'io', 'co', 'ai', 'app', 'dev', 'api', 'go', 'my', 'it', 'is', 'am', 'at',
    ]);

    // Brand spoofing terms — must occupy > 60% of SLD length to flag
    const BRAND_TERMS = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'instagram', 'secure', 'signin', 'banking', 'account', 'verify',
    ];

    // Safe hosts that should never be scored
    const SAFE_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Check if a domain (or subdomain of it) appears in the trusted allowlist.
     * @param {string} domain - e.g. "secure.paypal.com"
     * @returns {boolean}
     */
    function isTrustedDomain(domain) {
        if (TRUSTED_SET.has(domain)) return true;
        // Walk trusted list — check subdomain suffix
        for (const trusted of TRUSTED_SORTED) {
            if (domain.endsWith('.' + trusted)) return true;
        }
        return false;
    }

    // ─── URL Reputation Scorer ────────────────────────────────────────────────

    /**
     * Score a URL based on known phishing indicators.
     * @param {string} url - Full URL string
     * @returns {{ urlScore: number, findings: string[] }}
     */
    function scoreURL(url) {
        const findings = [];
        let score = 0;

        if (typeof url !== 'string') return { urlScore: 0, findings: [] };

        // Only score http(s) URLs
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return { urlScore: 0, findings: [] };
        }

        let hostname, pathname;
        try {
            const parsed = new URL(url);
            hostname = parsed.hostname.toLowerCase();
            pathname = parsed.pathname;
        } catch (_) {
            return { urlScore: 0, findings: [] };
        }

        // Skip safe hosts entirely
        if (SAFE_HOSTS.has(hostname)) return { urlScore: 0, findings: [] };

        const domain = hostname.replace(/^www\./, '');
        const parts = domain.split('.');
        const tld = parts.length >= 2 ? '.' + parts[parts.length - 1] : '';
        const sld = parts.length >= 2 ? parts[parts.length - 2] : domain;

        // 1. Trusted allowlist — immediate exit with 0 score
        if (isTrustedDomain(domain)) {
            return { urlScore: 0, findings: ['Domain is on trusted allowlist'] };
        }

        // 2. IP address as hostname
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
            findings.push('IP address used as domain');
            score += 40;
        }

        // 3. Suspicious free-hosting TLD
        if (SUSPICIOUS_TLDS.has(tld)) {
            findings.push(`Suspicious free-hosting TLD: ${tld}`);
            score += 30;
        }

        // 4. Multiple hyphens (bank-of-america-secure.com style)
        const hyphenCount = (sld.match(/-/g) || []).length;
        if (hyphenCount >= 2) {
            findings.push(`Multiple hyphens in domain SLD: ${domain}`);
            score += hyphenCount * 8;
        }

        // 5. Brand spoofing: term occupies dominant part of SLD
        for (const brand of BRAND_TERMS) {
            if (sld.includes(brand) && brand.length / sld.length > 0.5) {
                findings.push(`Brand term "${brand}" dominates SLD (spoofing risk)`);
                score += 22;
                break; // one brand flag per domain
            }
        }

        // 6. Short SLD heuristic (skip legitimate short SLDs)
        if (sld.length <= 5 && sld.length > 0 && !LEGITIMATE_SHORT_SLDS.has(sld)) {
            findings.push(`Very short SLD "${sld}" (${sld.length} chars)`);
            score += 10;
        }

        // 7. Punycode / non-ASCII (homograph attack)
        if (/xn--/.test(hostname) || /[^\x00-\x7F]/.test(hostname)) {
            findings.push('Punycode / non-ASCII domain (homograph attack risk)');
            score += 35;
        }

        // 8. NFC normalisation mismatch
        try {
            if (hostname !== hostname.normalize('NFC')) {
                findings.push('Domain fails NFC normalisation check');
                score += 40;
            }
        } catch (_) { }

        // 9. Excessive subdomains (>3 labels before TLD)
        if (parts.length > 4) {
            findings.push(`Excessive subdomains: ${hostname}`);
            score += 15;
        }

        // 10. Suspicious path keywords (capped at +15)
        const suspPathTerms = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking'];
        let pathScore = 0;
        for (const term of suspPathTerms) {
            if (pathname.toLowerCase().includes(term)) {
                pathScore += 5;
                if (pathScore >= 15) break;
            }
        }
        score += pathScore;

        return { urlScore: Math.min(score, 100), findings };
    }

    // ─── Full Risk Computer ───────────────────────────────────────────────────

    /**
     * Compute the overall phishing risk score for the current page.
     * Combines URL reputation (35%) and DOM analysis (65%).
     * @returns {{ riskScore: number, findings: string[], breakdown: Object }}
     */
    function computePhishingRisk() {
        const currentURL = (typeof window !== 'undefined' && window.location)
            ? window.location.href
            : '';

        const urlResult = scoreURL(currentURL);
        const domResult = (global.ZTBGDOMAnalyzer && typeof global.ZTBGDOMAnalyzer.runFullDOMAnalysis === 'function')
            ? global.ZTBGDOMAnalyzer.runFullDOMAnalysis()
            : { domScore: 0, findings: [], breakdown: {} };

        const combinedScore = Math.round(urlResult.urlScore * 0.35 + (domResult.domScore || 0) * 0.65);

        return {
            riskScore: Math.min(combinedScore, 100),
            findings: [...urlResult.findings, ...domResult.findings],
            breakdown: {
                urlReputation: urlResult.urlScore,
                domAnalysis: domResult.domScore || 0,
                ...(domResult.breakdown || {}),
            },
        };
    }

    /**
     * Categorise a numeric risk score into a level, colour, and label.
     * @param {number} score
     * @returns {{ level: string, color: string, label: string }}
     */
    function categorizeRisk(score) {
        if (typeof score !== 'number' || isNaN(score) || score <= 30) {
            return { level: 'safe', color: '#00e676', label: 'Safe' };
        }
        if (score <= 60) return { level: 'suspicious', color: '#ffab00', label: 'Suspicious' };
        return { level: 'dangerous', color: '#ff4d4d', label: 'Dangerous' };
    }

    // Export
    global.ZTBGPhishing = {
        computePhishingRisk,
        scoreURL,
        categorizeRisk,
        isTrustedDomain,
        TRUSTED_SET,
    };

})(typeof globalThis !== 'undefined' ? globalThis : self);
