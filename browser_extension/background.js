/**
 * SentinelClip — Background Service Worker (MV3)
 * 
 * Bridges the content script and native messaging host.
 * Receives file scan requests from content_script.js,
 * forwards them to the native messaging host for detection,
 * and returns the verdict (ALLOW / BLOCK / WARN).
 */

const NATIVE_HOST_NAME = 'com.sentinelclip.host';

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_FILE') {
        handleScanRequest(message.payload, sendResponse);
        return true; // Keep the message channel open for async response
    }
});

/**
 * Handle a file scan request from the content script.
 * Forwards the file content to the native messaging host for detection.
 */
async function handleScanRequest(payload, sendResponse) {
    try {
        const response = await sendToNativeHost({
            action: 'scan',
            domain: payload.domain,
            filename: payload.filename,
            content: payload.content,
            file_size: payload.fileSize,
        });

        if (response && response.verdict) {
            // Send verdict back to content script
            sendResponse({
                verdict: response.verdict,
                detections: response.detections || null,
                message: response.message || null,
            });

            // Show browser notification for BLOCK/WARN
            if (response.verdict === 'BLOCK') {
                showNotification(
                    'Upload Blocked',
                    `File "${payload.filename}" on ${payload.domain} was blocked due to sensitive content.`,
                    'error'
                );
            } else if (response.verdict === 'WARN') {
                showNotification(
                    'Sensitive Content Warning',
                    `File "${payload.filename}" may contain sensitive data.`,
                    'warning'
                );
            }
        } else {
            // Protected uploads must not bypass scanning when the host fails.
            console.warn('[SentinelClip] No valid response from native host');
            sendResponse({
                verdict: 'BLOCK',
                reason: 'native_host_no_response',
                message: 'SentinelClip could not verify this file upload.',
            });
        }
    } catch (error) {
        console.error('[SentinelClip] Native messaging error:', error);

        // The direct browser fallback has no device credential. Do not bypass
        // scanning when the native host is unavailable.
        sendResponse({
            verdict: 'BLOCK',
            reason: 'native_host_unavailable',
            message: 'SentinelClip native host is unavailable. Upload blocked.',
        });
    }
}

// ---------------------------------------------------------------------------
// Native messaging
// ---------------------------------------------------------------------------

/**
 * Send a message to the native messaging host and wait for a response.
 */
function sendToNativeHost(message) {
    return new Promise((resolve, reject) => {
        try {
            const port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
            let responded = false;

            port.onMessage.addListener((response) => {
                responded = true;
                port.disconnect();
                resolve(response);
            });

            port.onDisconnect.addListener(() => {
                if (!responded) {
                    const error = chrome.runtime.lastError;
                    reject(new Error(
                        error ? error.message : 'Native host disconnected without response'
                    ));
                }
            });

            port.postMessage(message);

            // Timeout after 10 seconds
            setTimeout(() => {
                if (!responded) {
                    port.disconnect();
                    reject(new Error('Native host timeout'));
                }
            }, 10000);
        } catch (error) {
            reject(error);
        }
    });
}

// ---------------------------------------------------------------------------
// Legacy direct API fallback is intentionally not used without a device token.
// ---------------------------------------------------------------------------

/**
 * Scan file content directly via the Flask API.
 * This is a fallback when native messaging is not set up.
 */
async function scanViaAPI(payload) {
    const response = await fetch('http://127.0.0.1:5000/api/v1/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            source: 'browser_upload',
            domain: payload.domain,
            detections: [],
            action_taken: 'SCAN_REQUESTED',
        }),
    });

    if (response.ok) {
        return { verdict: 'ALLOW', reason: 'api_fallback_logged' };
    }

    throw new Error(`API returned ${response.status}`);
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/**
 * Show a browser notification.
 */
function showNotification(title, message, type) {
    const iconUrl = type === 'error'
        ? 'icons/icon48.png'
        : 'icons/icon48.png';

    chrome.notifications?.create({
        type: 'basic',
        iconUrl: iconUrl,
        title: `SentinelClip — ${title}`,
        message: message,
        priority: type === 'error' ? 2 : 1,
    });
}

// ---------------------------------------------------------------------------
// Extension lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
    console.log('[SentinelClip] Extension installed / updated');
});

console.log('[SentinelClip] Background service worker loaded');
