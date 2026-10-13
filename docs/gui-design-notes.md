# Kiosk GUI — Design Notes and Deviations (Phase 5)

## Deviations from implementation plan v1.5

1. **No client-side QStateMachine.** The plan asks for a QStateMachine with 13 QStates.
   The orchestrator already owns the state machine and announces every state; a second
   transition graph in the GUI could diverge from it and would put logic into a component
   that must be a pure display client. The GUI maps each STATE_CHANGED to its screen and
   rejects unknown states.
2. **No GUI→LED bridge.** The LED service subscribes to the orchestrator state socket
   itself (Phase 6; `orchestrator.client_users` already lists `usbscan-led`), so a GUI
   crash cannot freeze the status light.
3. **Screens grouped in `screens.py`** instead of one file per state; all 13 states exist.
4. **Operator-hold timeout is not sent by the GUI.** The orchestrator enforces it; the GUI
   only shows the countdown.

## Security-relevant behaviour

- PIN pad: CSPRNG shuffle on every presentation, dots only, buffer cleared on every exit
  path, PIN goes to the orchestrator (persistent lockout there). Verified: 100 consecutive
  presentations, no two identical layouts, all ten digits present (AC-S06).
- Only the GUI uid may send operator messages (orchestrator side).
- Disconnected from the orchestrator → "Scanning unavailable"; no stale verdicts.
- Public screen shows counts, verdict and (configurable) detection names — never file
  paths, serials or raw payload values (spec §4.1, §4.4). Ambient mode after
  `gui.ambient_after_seconds` shows only station ID, time and health.
- Restricted extension scope is disclosed on the result screen (spec §6.2).

## Verified in CI

- 36 pytest-qt tests (offscreen), including a real IPCServer ↔ IpcWorker round trip.
- Rendered screenshots at 800×480 inspected; found and fixed: backgrounds painted only
  behind labels (needs `WA_StyledBackground`), translucent PIN overlay.
- Translations: `pyside6-lupdate` extracts all 68 strings in context `usbscan`; a German
  `.qm` loads and changes the result screen at runtime. Found and fixed: bare `tr("…")`
  calls were extracted with an empty context and would never have been translated.
- Real `python -m src.gui` process driven by `scripts/gui_demo.py`; clean SIGTERM exit.

## Open items

- **Which languages to ship** (spec §4.1 requires translation support; none besides
  English are included yet).
- Wayland kiosk compositor on the Pi (labwc vs. cage), app_id `usb-scan-kiosk`, touch
  calibration, portrait/landscape (Phase 10).
- Manual check of PIN randomization and touch long-press on the real 5" panel.
