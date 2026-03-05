/**
 * ZTBG — Shannon Entropy Calculator v1.0.1
 *
 * Fixes applied (Phases 2, 5):
 *  - NaN guard: returns 0 for empty/null strings (was already present, strengthened)
 *  - findHighEntropyTokens: skips tokens that look like hex colour codes,
 *    UUIDs, common base64 image data URIs, and pure numeric strings
 *    (reduces false positives per Phase 5A)
 *  - No console.log calls
 */

(function (global) {
    'use strict';

    // Patterns that look high-entropy but are safe/common — reduce false positives
    const FALSE_POSITIVE_PATTERNS = [
        /^#?[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$/, // Hex colour (#RRGGBB / #RRGGBBAA)
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID v4
        /^data:[a-z]+\/[a-z+]+;base64,/i,        // Base64 data URI prefix
        /^\d+$/,                                  // Pure numeric (phone, zip, etc.)
        /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/, // Email address
    ];

    /**
     * Calculates Shannon entropy of a string.
     * @param {string} str - Input string to measure
     * @returns {number} Entropy in bits per character (0 to ~6.5)
     */
    function shannonEntropy(str) {
        if (!str || typeof str !== 'string' || str.length === 0) return 0;

        const freq = Object.create(null);
        const len = str.length;

        for (let i = 0; i < len; i++) {
            const c = str[i];
            freq[c] = (freq[c] || 0) + 1;
        }

        let entropy = 0;
        for (const count of Object.values(freq)) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }

        return entropy; // Always finite for non-empty strings
    }

    /**
     * Returns true if the string is likely a secret based on entropy + length.
     * @param {string} str - Input string
     * @param {number} [entropyThreshold=4.5] - Minimum entropy score
     * @param {number} [minLength=20] - Minimum string length
     * @returns {boolean}
     */
    function isHighEntropySecret(str, entropyThreshold = 4.5, minLength = 20) {
        if (!str || typeof str !== 'string' || str.length < minLength) return false;
        if (FALSE_POSITIVE_PATTERNS.some(p => p.test(str))) return false;
        return shannonEntropy(str) > entropyThreshold;
    }

    /**
     * Classify entropy into a named level.
     * @param {number} entropy
     * @returns {'low'|'medium'|'high'|'critical'}
     */
    function classifyEntropy(entropy) {
        if (typeof entropy !== 'number' || isNaN(entropy)) return 'low';
        if (entropy < 3.0) return 'low';
        if (entropy < 4.5) return 'medium';
        if (entropy < 5.5) return 'high';
        return 'critical';
    }

    /**
     * Scan a block of text and return tokens with entropy > threshold.
     * Applies false-positive suppression filters.
     * @param {string} text - Body of text to scan
     * @param {number} [minLength=20] - Min token length
     * @returns {Array<{token: string, entropy: number, classification: string}>}
     */
    function findHighEntropyTokens(text, minLength = 20) {
        if (!text || typeof text !== 'string') return [];

        const tokens = text.split(/[\s,;"'`()\[\]{}<>|\\\/\r\n]+/);
        const results = [];

        for (const token of tokens) {
            if (token.length < minLength) continue;
            if (FALSE_POSITIVE_PATTERNS.some(p => p.test(token))) continue;

            const entropy = shannonEntropy(token);
            if (entropy > 4.5) {
                results.push({
                    token: token.substring(0, 40), // Never store full secrets in memory
                    entropy: Math.round(entropy * 100) / 100,
                    classification: classifyEntropy(entropy),
                });
            }
        }

        return results;
    }

    // Export
    global.ZTBGEntropy = {
        shannonEntropy,
        isHighEntropySecret,
        classifyEntropy,
        findHighEntropyTokens,
    };

})(typeof globalThis !== 'undefined' ? globalThis : self);
