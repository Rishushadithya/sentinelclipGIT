/**
 * SentinelClip — Content Script
 * 
 * Runs on matched AI domain pages (ChatGPT, Gemini, Claude, Copilot).
 * Detects file upload attempts via:
 *   1. <input type="file"> change events
 *   2. Drag-and-drop upload zones
 *   3. Paste events with file data
 * 
 * Reads file content (for supported text-based types) and sends it to
 * background.js for scanning via the native messaging host.
 */

(function() {
    'use strict';

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB limit for scanning
    const SUPPORTED_EXTENSIONS = [
        '.txt', '.csv', '.json', '.xml', '.yaml', '.yml',
        '.py', '.js', '.ts', '.jsx', '.tsx',
        '.java', '.cpp', '.c', '.h', '.hpp',
        '.cs', '.go', '.rs', '.rb', '.php',
        '.sql', '.sh', '.bat', '.ps1',
        '.env', '.cfg', '.ini', '.conf',
        '.md', '.rst', '.log',
    ];
    const SUPPORTED_MIME_PREFIXES = ['text/', 'application/json', 'application/xml'];

    // -----------------------------------------------------------------------
    // Utility functions
    // -----------------------------------------------------------------------

    /**
     * Check if a file is text-based and should be scanned.
     */
    function isScannable(file) {
        if (file.size > MAX_FILE_SIZE) {
            console.log(`[SentinelClip] Skipping ${file.name}: exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit`);
            return false;
        }

        // Check by extension
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        if (SUPPORTED_EXTENSIONS.includes(ext)) {
            return true;
        }

        // Check by MIME type
        if (file.type) {
            for (const prefix of SUPPORTED_MIME_PREFIXES) {
                if (file.type.startsWith(prefix)) {
                    return true;
                }
            }
        }

        console.log(`[SentinelClip] Skipping ${file.name}: unsupported type (${file.type || 'unknown'})`);
        return false;
    }

    /**
     * Read file content as text.
     */
    function readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsText(file);
        });
    }

    /**
     * Get the current AI domain.
     */
    function getCurrentDomain() {
        return window.location.hostname;
    }

    /**
     * Create a blocking overlay to prevent upload while scanning.
     */
    function showBlockOverlay(message) {
        // Remove existing overlay if any
        removeBlockOverlay();

        const overlay = document.createElement('div');
        overlay.id = 'sentinelclip-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        `;

        const card = document.createElement('div');
        card.style.cssText = `
            background: #1a1a2e;
            border: 2px solid #e94560;
            border-radius: 16px;
            padding: 40px;
            max-width: 480px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(233, 69, 96, 0.3);
        `;

        card.innerHTML = `
            <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
            <h2 style="color: #e94560; margin: 0 0 12px; font-size: 22px; font-weight: 700;">
                SentinelClip — Upload Blocked
            </h2>
            <p style="color: #a0a0b0; margin: 0 0 24px; font-size: 14px; line-height: 1.6;">
                ${message}
            </p>
            <button id="sentinelclip-dismiss" style="
                background: #e94560;
                color: white;
                border: none;
                padding: 12px 32px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.2s;
            ">Dismiss</button>
        `;

        overlay.appendChild(card);
        document.body.appendChild(overlay);

        document.getElementById('sentinelclip-dismiss').addEventListener('click', () => {
            removeBlockOverlay();
        });
    }

    /**
     * Show a warning notification (non-blocking).
     */
    function showWarningBanner(message) {
        const banner = document.createElement('div');
        banner.className = 'sentinelclip-warning';
        banner.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border: 1px solid #f0a500;
            border-radius: 12px;
            padding: 16px 24px;
            max-width: 380px;
            z-index: 2147483646;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            box-shadow: 0 8px 32px rgba(240, 165, 0, 0.2);
            animation: sentinelclip-slidein 0.3s ease-out;
        `;

        banner.innerHTML = `
            <div style="display: flex; align-items: start; gap: 12px;">
                <span style="font-size: 24px;">⚠️</span>
                <div>
                    <div style="color: #f0a500; font-weight: 600; font-size: 13px; margin-bottom: 4px;">
                        SentinelClip Warning
                    </div>
                    <div style="color: #a0a0b0; font-size: 12px; line-height: 1.5;">
                        ${message}
                    </div>
                </div>
                <button class="sentinelclip-close" style="
                    background: none;
                    border: none;
                    color: #666;
                    font-size: 18px;
                    cursor: pointer;
                    padding: 0;
                    line-height: 1;
                ">✕</button>
            </div>
        `;

        // Add slide-in animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes sentinelclip-slidein {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);

        document.body.appendChild(banner);

        banner.querySelector('.sentinelclip-close').addEventListener('click', () => {
            banner.remove();
        });

        // Auto-dismiss after 8 seconds
        setTimeout(() => {
            if (banner.parentNode) {
                banner.style.transition = 'opacity 0.3s';
                banner.style.opacity = '0';
                setTimeout(() => banner.remove(), 300);
            }
        }, 8000);
    }

    function removeBlockOverlay() {
        const overlay = document.getElementById('sentinelclip-overlay');
        if (overlay) overlay.remove();
    }

    // -----------------------------------------------------------------------
    // File scanning and messaging
    // -----------------------------------------------------------------------

    /**
     * Scan a file by sending its content to the background script.
     * Returns a promise that resolves with the verdict.
     */
    async function scanFile(file) {
        if (!isScannable(file)) {
            return { verdict: 'ALLOW', reason: 'unscannable_file_type' };
        }

        try {
            const content = await readFileAsText(file);
            const domain = getCurrentDomain();

            return new Promise((resolve) => {
                chrome.runtime.sendMessage(
                    {
                        type: 'SCAN_FILE',
                        payload: {
                            domain: domain,
                            filename: file.name,
                            content: content,
                            fileSize: file.size,
                        }
                    },
                    (response) => {
                        if (chrome.runtime.lastError) {
                            console.error('[SentinelClip] Message error:', chrome.runtime.lastError);
                            resolve({ verdict: 'ALLOW', reason: 'extension_error' });
                        } else {
                            resolve(response || { verdict: 'ALLOW', reason: 'no_response' });
                        }
                    }
                );
            });
        } catch (err) {
            console.error(`[SentinelClip] Error reading ${file.name}:`, err);
            return { verdict: 'ALLOW', reason: 'read_error' };
        }
    }

    /**
     * Handle file input change events.
     */
    async function handleFileInput(event) {
        const input = event.target;
        if (!input.files || input.files.length === 0) return;

        console.log(`[SentinelClip] File input detected: ${input.files.length} file(s)`);

        for (const file of input.files) {
            const result = await scanFile(file);
            console.log(`[SentinelClip] Verdict for ${file.name}: ${result.verdict}`);

            if (result.verdict === 'BLOCK') {
                // Clear the file input
                event.preventDefault();
                event.stopImmediatePropagation();
                input.value = '';
                showBlockOverlay(
                    `File <strong>${file.name}</strong> contains sensitive data ` +
                    `(${result.detections || 'policy violation'}). ` +
                    `Upload has been blocked to prevent data leakage.`
                );
                return;
            } else if (result.verdict === 'WARN') {
                showWarningBanner(
                    `File <strong>${file.name}</strong> may contain sensitive data. ` +
                    `Proceed with caution.`
                );
            }
        }
    }

    /**
     * Handle drag-and-drop file events.
     */
    async function handleDrop(event) {
        if (!event.dataTransfer || !event.dataTransfer.files || event.dataTransfer.files.length === 0) {
            return;
        }

        console.log(`[SentinelClip] Drop detected: ${event.dataTransfer.files.length} file(s)`);

        for (const file of event.dataTransfer.files) {
            const result = await scanFile(file);
            console.log(`[SentinelClip] Verdict for ${file.name}: ${result.verdict}`);

            if (result.verdict === 'BLOCK') {
                event.preventDefault();
                event.stopImmediatePropagation();
                showBlockOverlay(
                    `File <strong>${file.name}</strong> contains sensitive data ` +
                    `(${result.detections || 'policy violation'}). ` +
                    `Upload has been blocked to prevent data leakage.`
                );
                return;
            } else if (result.verdict === 'WARN') {
                showWarningBanner(
                    `File <strong>${file.name}</strong> may contain sensitive data. ` +
                    `Proceed with caution.`
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Event listeners
    // -----------------------------------------------------------------------

    // Listen for file input changes (captures existing and dynamically added inputs)
    document.addEventListener('change', (event) => {
        if (event.target && event.target.type === 'file') {
            handleFileInput(event);
        }
    }, true);

    // Listen for drag-and-drop
    document.addEventListener('drop', handleDrop, true);

    // Observe DOM for dynamically added file inputs
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;

                // Check the added node itself
                if (node.tagName === 'INPUT' && node.type === 'file') {
                    node.addEventListener('change', handleFileInput, true);
                }

                // Check children
                const fileInputs = node.querySelectorAll?.('input[type="file"]');
                if (fileInputs) {
                    fileInputs.forEach((input) => {
                        input.addEventListener('change', handleFileInput, true);
                    });
                }
            }
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
    });

    console.log('[SentinelClip] Content script loaded for', getCurrentDomain());
})();
