---
name: pyside6-statemachine
description: >-
  PySide6 kiosk GUI (src/gui): screens per orchestrator state, IPC worker thread,
  PIN overlay, operator panel, ambient mode, translations. Use when working on GUI
  states, the IPC event loop, the PIN overlay or GUI texts.
---

# PySide6 Kiosk GUI (as implemented — see docs/gui-design-notes.md)

## Rules
- The GUI is a pure display client. The ORCHESTRATOR owns the state machine; the GUI
  shows the screen for each STATE_CHANGED (validated against the 13 GUIState values) and
  renders payloads. Do not re-implement transitions or any scan logic in src/gui/.
- Outbound messages are only OPERATOR_PIN_SUBMIT, OPERATOR_ACK, LOCKOUT_QUERY.
- IPC runs in `IpcWorker` (QThread + asyncio IPCClient); events reach the UI thread only
  through the `event_received` signal. Never block the UI thread.
- IPC_DISCONNECTED → "Scanning unavailable" screen; never keep a stale result.
- Never render file paths, device serials or raw payloads. Only the keys each screen reads.

## PIN overlay (widgets/pin_overlay.py)
- `secrets.SystemRandom().shuffle` on EVERY `open()` (AC-S06); dots only; min/max length
  from cfg.pin; buffer cleared on submit/cancel/hide; PIN verified by the orchestrator only.
- Long-press area: 96×96 px in IDLE, `gui.long_press_ms` (default 3000).

## Operator hold
- Countdown shows `remaining_s`; the timeout is enforced by the orchestrator.
- Ack button appears only after a successful PIN while OPERATOR_HOLD is active.

## Styling
- Full-screen colour + icon + text per state/verdict (presentation.py). Screens need
  `WA_StyledBackground` + `#objectName` selectors, otherwise only labels get the colour.
- Touch targets ≥ 48 px (keypad 72 px).

## Translations
- Literals: `QCoreApplication.translate("usbscan", "...")`; table strings:
  `QT_TRANSLATE_NOOP("usbscan", "...")` rendered with `tr()`. Bare `tr("...")` is NOT
  extracted with the right context (test guards this). Tooling: scripts/update-translations.sh.

## Testing
QT_QPA_PLATFORM=offscreen + pytest-qt; scripts/gui_demo.py cycles all states for manual runs.
