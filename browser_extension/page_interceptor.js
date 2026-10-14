/**
 * SentinelClip — Page Interceptor (Main World)
 * 
 * Runs in the webpage's MAIN WORLD context at document_start.
 * Intercepts:
 *   1. <input type="file"> change/input events before React or page scripts receive them.
 *   2. window.showOpenFilePicker (File System Access API).
 *   3. Drag-and-drop file uploads (drop event).
 *   4. Paste events containing files or text.
 *   5. Network upload attempts (fetch and XMLHttpRequest with FormData/Blob).
 * 
 * Communicates with content_script.js via window.postMessage.
 */

(function() {
    'use strict';

    if (window.__sentinelclip_page_interceptor_loaded) {
        return;
    }
    window.__sentinelclip_page_interceptor_loaded = true;

    console.log('[SentinelClip] Page interceptor initialized in main world for', window.location.hostname);

    const VERIFIED_EVENT_FLAG = '__sentinelclip_verified';
    const VERIFIED_INPUT_FLAG = '__sentinelclip_input_verified';
    const VERIFIED_DROP_FLAG = '__sentinelclip_drop_verified';
    const VERIFIED_PASTE_FLAG = '__sentinelclip_paste_verified';

    const approvedFiles = new WeakSet();
    const blockedFiles = new WeakSet();

    let scanRequestId = 0;
    const pendingScans = new Map();

    // -----------------------------------------------------------------------
    // PostMessage Bridge to content_script.js
    // -----------------------------------------------------------------------

    function sendScanRequest(file) {
        return new Promise((resolve) => {
            const id = 'sc_' + Date.now() + '_' + (++scanRequestId);
            
            // Fail-closed timeout (15s)
            const timer = setTimeout(() => {
                if (pendingScans.has(id)) {
                    pendingScans.delete(id);
                    console.warn(`[SentinelClip] Scan timeout for ${file.name}; failing closed.`);
                    resolve({
                        verdict: 'BLOCK',
                        reason: 'scan_timeout',
                        message: `SentinelClip scan timed out for ${file.name}. Upload blocked for security.`
                    });
                }
            }, 15000);

            pendingScans.set(id, (response) => {
                clearTimeout(timer);
                resolve(response);
            });

            window.postMessage({
                source: 'SENTINELCLIP_PAGE',
                type: 'SCAN_FILE_REQUEST',
                id: id,
                file: file,
                filename: file.name,
                fileSize: file.size,
                fileType: file.type || 'application/octet-stream',
                domain: window.location.hostname
            }, '*');
        });
    }

    function triggerBlockOverlay(message) {
        window.postMessage({
            source: 'SENTINELCLIP_PAGE',
            type: 'SHOW_BLOCK_OVERLAY',
            message: message
        }, '*');
    }

    function triggerWarningBanner(message) {
        window.postMessage({
            source: 'SENTINELCLIP_PAGE',
            type: 'SHOW_WARN_BANNER',
            message: message
        }, '*');
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data || event.data.source !== 'SENTINELCLIP_EXT') {
            return;
        }

        if (event.data.type === 'SCAN_FILE_RESPONSE') {
            const callback = pendingScans.get(event.data.id);
            if (callback) {
                pendingScans.delete(event.data.id);
                callback(event.data.verdict);
            }
        }
    });

    // -----------------------------------------------------------------------
    // 1. Intercept <input type="file"> (The "+" icon upload flow)
    // -----------------------------------------------------------------------

    async function handleFileInputCapture(event) {
        const input = event.target;
        if (!input || input.tagName !== 'INPUT' || input.type !== 'file') {
            return;
        }

        // If this event was already scanned and re-dispatched by us, let it pass to React/page!
        if (event[VERIFIED_EVENT_FLAG] || input[VERIFIED_INPUT_FLAG]) {
            delete input[VERIFIED_INPUT_FLAG];
            return;
        }

        if (!input.files || input.files.length === 0) {
            return;
        }

        // CRITICAL: Stop the event IMMEDIATELY in the window capture phase!
        // This stops React / ChatGPT / Claude / Gemini from receiving the change/input event.
        event.stopImmediatePropagation();
        event.stopPropagation();
        event.preventDefault();

        const selectedFiles = Array.from(input.files);
        console.log(`[SentinelClip] Intercepted file input change with ${selectedFiles.length} file(s)`);

        // Clear input value so nothing is accessible while scanning
        try {
            input.value = '';
        } catch (_) {}

        let allAllowed = true;
        let blockReason = '';

        for (const file of selectedFiles) {
            const result = await sendScanRequest(file);
            console.log(`[SentinelClip] File "${file.name}" verdict:`, result.verdict);

            if (result.verdict === 'BLOCK') {
                allAllowed = false;
                blockedFiles.add(file);
                blockReason = result.message ||
                    `File "${file.name}" contains sensitive content (${result.detections || 'policy violation'}). Upload blocked.`;
                break;
            } else if (result.verdict === 'WARN') {
                approvedFiles.add(file);
                triggerWarningBanner(
                    `File "${file.name}" may contain sensitive data. Proceed with caution.`
                );
            } else {
                approvedFiles.add(file);
            }
        }

        if (!allAllowed) {
            console.warn('[SentinelClip] Upload BLOCKED:', blockReason);
            try {
                input.value = '';
            } catch (_) {}
            triggerBlockOverlay(blockReason);
            return; // DO NOT REPLAY! Upload completely stopped before touching the AI.
        }

        // All files passed: restore files to the input element and replay event to React
        try {
            const dt = new DataTransfer();
            selectedFiles.forEach((f) => dt.items.add(f));
            input.files = dt.files;
        } catch (e) {
            console.error('[SentinelClip] Could not restore files via DataTransfer:', e);
        }

        input[VERIFIED_INPUT_FLAG] = true;

        const replayChange = new Event('change', { bubbles: true, cancelable: false });
        replayChange[VERIFIED_EVENT_FLAG] = true;
        input.dispatchEvent(replayChange);

        const replayInput = new Event('input', { bubbles: true, cancelable: false });
        replayInput[VERIFIED_EVENT_FLAG] = true;
        input.dispatchEvent(replayInput);
    }

    // Attach capture listeners on window - executes BEFORE any React root or DOM listeners
    window.addEventListener('change', handleFileInputCapture, true);
    window.addEventListener('input', handleFileInputCapture, true);

    // -----------------------------------------------------------------------
    // 2. Intercept window.showOpenFilePicker (File System Access API)
    // -----------------------------------------------------------------------

    if (window.showOpenFilePicker) {
        const origShowOpenFilePicker = window.showOpenFilePicker;
        window.showOpenFilePicker = async function(...args) {
            const handles = await origShowOpenFilePicker.apply(this, args);
            if (!handles || handles.length === 0) return handles;

            const allowedHandles = [];
            for (const handle of handles) {
                try {
                    const file = await handle.getFile();
                    const result = await sendScanRequest(file);

                    if (result.verdict === 'BLOCK') {
                        blockedFiles.add(file);
                        const blockMsg = result.message ||
                            `File "${file.name}" contains sensitive data. Upload blocked by SentinelClip.`;
                        triggerBlockOverlay(blockMsg);
                        throw new DOMException('Upload blocked by SentinelClip security policy.', 'AbortError');
                    } else if (result.verdict === 'WARN') {
                        approvedFiles.add(file);
                        triggerWarningBanner(`File "${file.name}" may contain sensitive data.`);
                        allowedHandles.push(handle);
                    } else {
                        approvedFiles.add(file);
                        allowedHandles.push(handle);
                    }
                } catch (err) {
                    if (err.name === 'AbortError') throw err;
                    console.error('[SentinelClip] Error inspecting file handle:', err);
                    throw new DOMException('Upload blocked by SentinelClip.', 'AbortError');
                }
            }

            return allowedHandles;
        };
    }

    // -----------------------------------------------------------------------
    // 3. Intercept Drag and Drop
    // -----------------------------------------------------------------------

    async function handleDropCapture(event) {
        if (event[VERIFIED_DROP_FLAG]) {
            return;
        }

        if (!event.dataTransfer || !event.dataTransfer.files || event.dataTransfer.files.length === 0) {
            return;
        }

        event.stopImmediatePropagation();
        event.stopPropagation();
        event.preventDefault();

        const files = Array.from(event.dataTransfer.files);
        console.log(`[SentinelClip] Intercepted drop event with ${files.length} file(s)`);

        let allAllowed = true;
        let blockReason = '';

        for (const file of files) {
            const result = await sendScanRequest(file);
            if (result.verdict === 'BLOCK') {
                allAllowed = false;
                blockedFiles.add(file);
                blockReason = result.message || `File "${file.name}" contains sensitive content. Upload blocked.`;
                break;
            } else if (result.verdict === 'WARN') {
                approvedFiles.add(file);
                triggerWarningBanner(`File "${file.name}" may contain sensitive data.`);
            } else {
                approvedFiles.add(file);
            }
        }

        if (!allAllowed) {
            triggerBlockOverlay(blockReason);
            return;
        }

        // Replay drop with verified flag
        const dt = new DataTransfer();
        files.forEach((f) => dt.items.add(f));
        const target = event.target || document.body;
        const replayDrop = new DragEvent('drop', {
            bubbles: true,
            cancelable: true,
            dataTransfer: dt,
            clientX: event.clientX,
            clientY: event.clientY,
        });
        replayDrop[VERIFIED_DROP_FLAG] = true;
        target.dispatchEvent(replayDrop);
    }

    window.addEventListener('drop', handleDropCapture, true);

    // -----------------------------------------------------------------------
    // 4. Intercept Paste (Files & Clipboard Text)
    // -----------------------------------------------------------------------

    async function handlePasteCapture(event) {
        if (event[VERIFIED_PASTE_FLAG]) {
            return;
        }

        const clipboardData = event.clipboardData;
        if (!clipboardData) return;

        // If files are pasted
        if (clipboardData.files && clipboardData.files.length > 0) {
            event.stopImmediatePropagation();
            event.stopPropagation();
            event.preventDefault();

            const files = Array.from(clipboardData.files);
            console.log(`[SentinelClip] Intercepted paste with ${files.length} file(s)`);

            let allAllowed = true;
            let blockReason = '';

            for (const file of files) {
                const result = await sendScanRequest(file);
                if (result.verdict === 'BLOCK') {
                    allAllowed = false;
                    blockedFiles.add(file);
                    blockReason = result.message || `Pasted file "${file.name}" was blocked by SentinelClip.`;
                    break;
                } else if (result.verdict === 'WARN') {
                    approvedFiles.add(file);
                    triggerWarningBanner(`Pasted file "${file.name}" may contain sensitive data.`);
                } else {
                    approvedFiles.add(file);
                }
            }

            if (!allAllowed) {
                triggerBlockOverlay(blockReason);
                return;
            }

            const dt = new DataTransfer();
            files.forEach((f) => dt.items.add(f));
            const target = event.target || document.activeElement || document.body;
            const replay = new ClipboardEvent('paste', {
                bubbles: true,
                cancelable: true,
                clipboardData: dt,
            });
            replay[VERIFIED_PASTE_FLAG] = true;
            target.dispatchEvent(replay);
            return;
        }

        // If plain text is pasted into prompt area, check for sensitive secrets
        const pastedText = clipboardData.getData('text/plain');
        if (pastedText && pastedText.trim().length > 8) {
            // Check for API keys, passwords, credentials in pasted prompt
            const virtualFile = new File([pastedText], 'pasted_prompt.txt', { type: 'text/plain' });
            sendScanRequest(virtualFile).then((result) => {
                if (result.verdict === 'BLOCK') {
                    triggerBlockOverlay(result.message || 'Pasted content contains sensitive data and was flagged by SentinelClip.');
                } else if (result.verdict === 'WARN') {
                    triggerWarningBanner('Pasted content may contain sensitive data.');
                }
            });
        }
    }

    window.addEventListener('paste', handlePasteCapture, true);

    // -----------------------------------------------------------------------
    // 5. Network Layer Fallback (fetch & XMLHttpRequest)
    // -----------------------------------------------------------------------

    const origFormDataAppend = FormData.prototype.append;
    FormData.prototype.append = function(name, value, filename) {
        if ((value instanceof File || value instanceof Blob) && blockedFiles.has(value)) {
            console.warn('[SentinelClip] Blocked file append in FormData prevented');
            return;
        }
        return origFormDataAppend.apply(this, arguments);
    };

    const origFetch = window.fetch;
    window.fetch = async function(resource, init) {
        if (init && init.body) {
            const body = init.body;
            if (body instanceof FormData) {
                for (const [key, val] of body.entries()) {
                    if ((val instanceof File || val instanceof Blob) && blockedFiles.has(val)) {
                        triggerBlockOverlay('Upload blocked by SentinelClip: sensitive file detected.');
                        throw new Error('SentinelClip: Upload blocked by security policy.');
                    }
                }
            } else if ((body instanceof File || body instanceof Blob) && blockedFiles.has(body)) {
                triggerBlockOverlay('Upload blocked by SentinelClip: sensitive file detected.');
                throw new Error('SentinelClip: Upload blocked by security policy.');
            }
        }
        return origFetch.apply(this, arguments);
    };

    const origXhrSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        if (body) {
            if (body instanceof FormData) {
                for (const [key, val] of body.entries()) {
                    if ((val instanceof File || val instanceof Blob) && blockedFiles.has(val)) {
                        triggerBlockOverlay('Upload blocked by SentinelClip: sensitive file detected.');
                        this.abort();
                        throw new Error('SentinelClip: Upload blocked by security policy.');
                    }
                }
            } else if ((body instanceof File || body instanceof Blob) && blockedFiles.has(body)) {
                triggerBlockOverlay('Upload blocked by SentinelClip: sensitive file detected.');
                this.abort();
                throw new Error('SentinelClip: Upload blocked by security policy.');
            }
        }
        return origXhrSend.apply(this, arguments);
    };

})();
