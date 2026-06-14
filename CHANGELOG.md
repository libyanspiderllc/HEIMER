# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-06-14

### Added
- **WAF Highlighting**:
    - Automatic identification and highlighting of Cloudflare (Cyan) and Sucuri (Green) IP addresses.
    - Safety logical checks that prevent accidental blocking of WAF IP ranges in CSF.
    - Activity logs now output a warning when a WAF-protected IP block is attempted and ignored.
- **Server Metrics Widget**:
    - Widget to monitor System CPU Load (1m, 5m, 15m) and Apache performance (Busy/Idle Workers, Req/s).
    - Metrics are fetched asynchronously using `?auto` status page to prevent TUI hangs.
- **GeoIP & ASN Lookup**:
    - Integrated on-demand GeoIP tool using `ip-api.com` in a modal window (Hotkey: `g`).
- **Auto-Refresh**:
    - Toggable Auto-Refresh functionality (Hotkey: `A`) with a default 5-second interval.
    - Visual status indicator in the metrics bar showing "AUTO ON/OFF".
- **Handle Apache Status Page Obfuscation in cPanel 136**:
    - Logic to handle obfuscated Apache Status URLs by reading keys from `/var/cpanel/whm_server_status_key`.
- **UI/UX Enhancements**:
    - Enabled Command Palette (`Ctrl+P`) for fuzzy-searching actions and shortcuts.
    - Dynamic version loading: App now automatically displays versioning from `VERSION.txt`.
    - CATEGORIZED help screen with improved readability and "Tips" section for `Shift+Click` clipboard usage.
    - Pruned footer shortcuts to avoid overflow while keeping all hotkeys functional.

### Changed
- Increased default IP column width from 20 to 35.
- Footer now displays only essential primary actions to prevent truncation on smaller terminals.
- Help screen now includes categories and more detailed descriptions.

### Fixed
- Selection logic stability when refreshing the table display.
- IP addressing sanitization when stripping WAF labels for downstream actions (WHOIS/CSF).
- Port filtering logic to better handle server-own IP exclusions.
