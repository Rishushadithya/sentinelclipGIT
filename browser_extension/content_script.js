/**
 * SentinelClip — Content Script (Isolated World)
 * 
 * Runs on matched AI domain pages (ChatGPT, Gemini, Claude, Copilot).
 * Coordinates with page_interceptor.js in the main world and forwards
 * file scanning requests to background.js and the native messaging host.
 * 
 * Features:
 *   1. Bridge between page context and background service worker.
 *   2. Fail-closed scan execution (never fails open on communication errors).
 *   3. High-contrast UI overlay for blocked uploads.
 *   4. Defense-in-depth local DOM event monitoring.
 */

(function() {
    'use strict';

    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB limit for scanning

    // -----------------------------------------------------------------------
    // Inject Main-World Page Interceptor
    // -----------------------------------------------------------------------

    function injectPageInterceptor() {
        try {
            const script = document.createElement('script');
            script.src = chrome.runtime.getURL('page_interceptor.js');
            script.onload = function() {
                this.remove();
            };
            (document.head || document.documentElement).appendChild(script);
        } catch (err) {
            console.error('[SentinelClip] Failed to inject page_interceptor.js:', err);
        }
    }

    injectPageInterceptor();

    // -----------------------------------------------------------------------
    // File Reading & Scanning
    // -----------------------------------------------------------------------

    /**
     * Read file content as text safely.
     */
    function readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result || '');
            reader.onerror = () => reject(reader.error);
            reader.readAsText(file);
        });
    }

    /**
     * Scan a file via background.js and native messaging host.
     */
    async function scanFile(file, domain) {
        if (!file) {
            return { verdict: 'ALLOW', reason: 'empty_file' };
        }

        if (file.size > MAX_FILE_SIZE) {
            return {
                verdict: 'BLOCK',
                reason: 'file_too_large',
                message: `Upload blocked: "${file.name}" exceeds the ${MAX_FILE_SIZE / (1024 * 1024)}MB scan limit.`
            };
        }

        let content = '';
        try {
            content = await readFileAsText(file);
        } catch (readErr) {
            console.error(`[SentinelClip] Error reading ${file.name}:`, readErr);
            // Fail-closed for security
            return {
                verdict: 'BLOCK',
                reason: 'read_error',
                message: `SentinelClip could not inspect "${file.name}". Upload blocked for security.`
            };
        }

        return new Promise((resolve) => {
            chrome.runtime.sendMessage(
                {
                    type: 'SCAN_FILE',
                    payload: {
                        domain: domain || window.location.hostname,
                        filename: file.name,
                        content: content,
                        fileSize: file.size,
                    }
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('[SentinelClip] Native host communication error:', chrome.runtime.lastError);
                        // Security policy: fail-closed when communication fails
                        resolve({
                            verdict: 'BLOCK',
                            reason: 'native_host_error',
                            message: `SentinelClip protection service error. Upload of "${file.name}" blocked to prevent data leak.`
                        });
                    } else if (response) {
                        resolve(response);
                    } else {
                        resolve({
                            verdict: 'BLOCK',
                            reason: 'no_response',
                            message: `SentinelClip received no response from scanner. Upload of "${file.name}" blocked.`
                        });
                    }
                }
            );
        });
    }

    // -----------------------------------------------------------------------
    // UI Notifications (Overlay & Banner)
    // -----------------------------------------------------------------------

    function removeBlockOverlay() {
        const existing = document.getElementById('sentinelclip-overlay');
        if (existing) {
            existing.remove();
        }
    }

    function showBlockOverlay(message) {
        removeBlockOverlay();

        const overlay = document.createElement('div');
        overlay.id = 'sentinelclip-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(10, 10, 20, 0.92);
            backdrop-filter: blur(8px);
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        `;

        const card = document.createElement('div');
        card.style.cssText = `
            background: #141726;
            border: 2px solid #ef4444;
            border-radius: 16px;
            padding: 36px 32px;
            max-width: 500px;
            width: 90%;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.35);
            animation: sentinelclip-fade-in 0.25s ease-out;
        `;

        card.innerHTML = `
            <div style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 12px; font-weight: 700; color: #ef4444; letter-spacing: 1px; margin-bottom: 12px;">[SECURITY ENFORCEMENT // BLOCK]</div>
            <h2 style="color: #ef4444; margin: 0 0 14px; font-size: 22px; font-weight: 700; letter-spacing: -0.02em;">
                SentinelClip — Upload Blocked
            </h2>
            <div style="color: #cbd5e1; margin: 0 0 24px; font-size: 14px; line-height: 1.6; word-break: break-word; background: rgba(239, 68, 68, 0.08); padding: 14px 18px; border-radius: 8px; border: 1px solid rgba(239, 68, 68, 0.2);">
                ${escapeHtml(message)}
            </div>
            <div style="display: flex; justify-content: center; gap: 12px;">
                <button id="sentinelclip-dismiss" style="
                    background: #ef4444;
                    color: white;
                    border: none;
                    padding: 11px 28px;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: background 0.15s ease-in-out;
                ">Dismiss & Acknowledge</button>
            </div>
        `;

        overlay.appendChild(card);
        (document.body || document.documentElement).appendChild(overlay);

        const dismissBtn = document.getElementById('sentinelclip-dismiss');
        if (dismissBtn) {
            dismissBtn.addEventListener('click', removeBlockOverlay);
            dismissBtn.addEventListener('mouseover', () => { dismissBtn.style.background = '#dc2626'; });
            dismissBtn.addEventListener('mouseout', () => { dismissBtn.style.background = '#ef4444'; });
        }
    }

    function showWarningBanner(message) {
        const existing = document.querySelector('.sentinelclip-warning');
        if (existing) existing.remove();

        const banner = document.createElement('div');
        banner.className = 'sentinelclip-warning';
        banner.style.cssText = `
            position: fixed;
            top: 24px;
            right: 24px;
            background: #181d30;
            border: 1px solid #f59e0b;
            border-radius: 12px;
            padding: 16px 20px;
            max-width: 420px;
            z-index: 2147483646;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            box-shadow: 0 10px 25px -5px rgba(245, 158, 11, 0.25);
            display: flex;
            align-items: start;
            gap: 12px;
        `;

        banner.innerHTML = `
            <span style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; font-weight: 700; color: #f59e0b; padding-top: 2px;">[WARN]</span>
            <div style="flex: 1;">
                <div style="color: #f59e0b; font-weight: 600; font-size: 13px; margin-bottom: 4px;">
                    SentinelClip Warning
                </div>
                <div style="color: #e2e8f0; font-size: 13px; line-height: 1.5;">
                    ${escapeHtml(message)}
                </div>
            </div>
            <button class="sentinelclip-close" style="
                background: none;
                border: none;
                color: #94a3b8;
                font-size: 18px;
                cursor: pointer;
                padding: 0 4px;
                line-height: 1;
            ">✕</button>
        `;

        (document.body || document.documentElement).appendChild(banner);

        banner.querySelector('.sentinelclip-close').addEventListener('click', () => {
            banner.remove();
        });

        setTimeout(() => {
            if (banner.parentNode) {
                banner.style.transition = 'opacity 0.4s';
                banner.style.opacity = '0';
                setTimeout(() => banner.remove(), 400);
            }
        }, 8000);
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // -----------------------------------------------------------------------
    // PostMessage Bridge Listener
    // -----------------------------------------------------------------------

    window.addEventListener('message', async (event) => {
        if (event.source !== window || !event.data || event.data.source !== 'SENTINELCLIP_PAGE') {
            return;
        }

        if (event.data.type === 'SCAN_FILE_REQUEST') {
            const { id, file, domain } = event.data;
            const verdict = await scanFile(file, domain);

            if (verdict.verdict === 'BLOCK') {
                showBlockOverlay(verdict.message || `File "${file.name}" blocked by SentinelClip.`);
            } else if (verdict.verdict === 'WARN') {
                showWarningBanner(verdict.message || `File "${file.name}" may contain sensitive data.`);
            }

            window.postMessage({
                source: 'SENTINELCLIP_EXT',
                type: 'SCAN_FILE_RESPONSE',
                id: id,
                verdict: verdict
            }, '*');
        } else if (event.data.type === 'SHOW_BLOCK_OVERLAY') {
            showBlockOverlay(event.data.message);
        } else if (event.data.type === 'SHOW_WARN_BANNER') {
            showWarningBanner(event.data.message);
        }
    });

    console.log('[SentinelClip] Content script ready on', window.location.hostname);
})();
