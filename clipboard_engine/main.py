"""
SentinelClip — Clipboard Sentinel Engine (Main Entrypoint)

Background process that monitors the OS clipboard for sensitive content.

Pipeline:
  1. Watcher detects clipboard change
  2. Detector scans against policy rules
  3. Sanitizer applies REDACT/OBFUSCATE/BLOCK/WARN actions
  4. Reporter posts event to Flask API hub
  5. If needed, clipboard is overwritten with sanitized content

Fail-safe behavior:
  - HIGH severity + API unreachable → fail-closed (block/clear clipboard)
  - LOW/MEDIUM + API unreachable → fail-open with console warning
"""

import sys
import os
import time
import logging
import pyperclip

# Fix Windows console encoding
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clipboard_engine.watcher import ClipboardWatcher
from clipboard_engine.detector import PolicyCache, detect_sensitive_content
from clipboard_engine.sanitizer import sanitize_payload
from clipboard_engine.reporter import report_detection, check_api_health

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinelclip.engine")

# ANSI colors for console output
COLORS = {
    "HIGH": "\033[91m",      # Red
    "MEDIUM": "\033[93m",    # Yellow
    "LOW": "\033[94m",       # Blue
    "RESET": "\033[0m",
    "GREEN": "\033[92m",
    "BOLD": "\033[1m",
}


def colorize(text: str, severity: str) -> str:
    """Add ANSI color based on severity."""
    color = COLORS.get(severity, COLORS["RESET"])
    return f"{color}{text}{COLORS['RESET']}"


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class SentinelClipEngine:
    """
    Main clipboard monitoring engine.
    
    Coordinates watcher, detector, sanitizer, and reporter components.
    """

    def __init__(self, api_base: str = "http://127.0.0.1:5000/api/v1"):
        self.api_base = api_base
        self.policy_cache = PolicyCache(api_base=api_base)
        self.event_count = 0
        self.block_count = 0

    def handle_clipboard_change(self, text: str):
        """
        Called by the watcher when clipboard content changes.
        Runs the full detection → sanitization → reporting pipeline.
        """
        start_time = time.perf_counter()

        # Get rules and scan
        rules = self.policy_cache.get_rules()
        if not rules:
            return  # No rules available

        # Run sanitization (includes detection)
        sanitized_text, detections_log = sanitize_payload(text, rules)

        # Filter out meta entries to get actual rule detections
        rule_detections = [d for d in detections_log if "rule_name" in d]

        if not rule_detections:
            return  # No sensitive content found

        # Determine highest severity and primary action
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_severity = max(
            (d.get("severity", "LOW") for d in rule_detections),
            key=lambda s: severity_order.get(s, 0),
        )
        has_block = any(d.get("type") == "block_required" for d in detections_log)
        has_warn = any(d.get("type") == "warning_required" for d in detections_log)

        # Determine action taken
        if has_block:
            action_taken = "BLOCK"
        elif sanitized_text != text:
            action_taken = "REDACT" if "[REDACTED]" in sanitized_text else "OBFUSCATE"
        elif has_warn:
            action_taken = "WARN"
        else:
            action_taken = "NONE"

        # Apply clipboard modification
        if has_block or sanitized_text != text:
            try:
                pyperclip.copy(sanitized_text)
                logger.info(
                    colorize(
                        f"[X] CLIPBOARD MODIFIED -- {action_taken} "
                        f"({len(rule_detections)} rule(s) triggered, "
                        f"severity: {max_severity})",
                        max_severity,
                    )
                )
            except Exception as e:
                logger.error(f"Failed to modify clipboard: {e}")
        elif has_warn:
            logger.info(
                colorize(
                    f"[!] WARNING -- {len(rule_detections)} detection(s) "
                    f"(severity: {max_severity}) -- content allowed",
                    max_severity,
                )
            )

        # Log each detection
        for det in rule_detections:
            logger.info(
                colorize(
                    f"  --> {det['rule_name']} [{det['severity']}] --> {det['action']}",
                    det.get("severity", "LOW"),
                )
            )

        # Report to API
        api_reachable = self.policy_cache.is_api_reachable()
        if api_reachable:
            report_detection(
                detections=rule_detections,
                source="clipboard",
                action_taken=action_taken,
                api_base=self.api_base,
            )
        else:
            # Fail-safe behavior
            if max_severity == "HIGH":
                # Fail-closed: block content even without API
                try:
                    pyperclip.copy(
                        "[BLOCKED — SentinelClip API unreachable, "
                        "HIGH severity content cleared for safety]"
                    )
                    logger.warning(
                        colorize(
                            "[X] API UNREACHABLE -- HIGH severity content "
                            "blocked (fail-closed)",
                            "HIGH",
                        )
                    )
                except Exception:
                    pass
            else:
                logger.warning(
                    colorize(
                        f"[!] API UNREACHABLE -- {max_severity} severity "
                        f"content allowed (fail-open)",
                        max_severity,
                    )
                )

        # Performance logging
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        self.event_count += 1
        if has_block:
            self.block_count += 1
        logger.debug(f"Pipeline completed in {elapsed_ms:.1f}ms")

        if elapsed_ms > 150:
            logger.warning(
                f"[!] Pipeline latency {elapsed_ms:.1f}ms exceeds 150ms target"
            )

    def run(self):
        """Start the clipboard monitoring engine."""
        print()
        print(f"{COLORS['BOLD']}{'=' * 60}")
        print("  SentinelClip -- Clipboard Sentinel Engine")
        print(f"{'=' * 60}{COLORS['RESET']}")
        print()

        # Check API health
        if check_api_health(self.api_base):
            print(f"  {COLORS['GREEN']}[OK] Flask API Hub is reachable{COLORS['RESET']}")
        else:
            print(
                f"  {COLORS['HIGH']}[X] Flask API Hub is NOT reachable{COLORS['RESET']}"
            )
            print(
                f"  {COLORS['HIGH']}  Start it with: "
                f"py -m api.app{COLORS['RESET']}"
            )
            print()

        # Load initial rules
        rules = self.policy_cache.get_rules()
        print(f"  Loaded {len(rules)} policy rules")
        print(f"  Monitoring clipboard... (Ctrl+C to stop)")
        print()

        # Start watcher
        watcher = ClipboardWatcher(
            on_change=self.handle_clipboard_change,
            poll_interval=0.2,
        )

        try:
            watcher.start()
        except KeyboardInterrupt:
            watcher.stop()
            print()
            print(f"{COLORS['BOLD']}Session Summary:{COLORS['RESET']}")
            print(f"  Events processed: {self.event_count}")
            print(f"  Blocks applied:   {self.block_count}")
            print()


if __name__ == "__main__":
    engine = SentinelClipEngine()
    engine.run()
