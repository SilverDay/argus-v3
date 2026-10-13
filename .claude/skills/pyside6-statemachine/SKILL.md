---
name: pyside6-statemachine
description: >-
  PySide6 state machine pattern for the kiosk GUI. Use when working on
  GUI states, transitions, animations, the IPC event loop, or PIN overlay.
  Note: spec uses PySide6 (preferred), not PyQt6. API is nearly identical.
---

# PySide6 GUI State Machine

## States (13 total — src/gui/state_machine.py)
STARTING | NOT_READY | IDLE | VALIDATING | MOUNTING | SCANNING | EVALUATING |
OPERATOR_HOLD | EJECTING | RESULT | EJECT_FAILED | REJECTED | ERROR
Defined as QState objects; transitions driven by ScanEvent objects from IPC socket.

## Rules
- NEVER call scan logic, broker RPC, or mount operations from GUI code.
- All state transitions driven by ScanEvent objects received on the IPC state socket.
- Use QPropertyAnimation for transitions — no blocking calls on the UI thread.
- IPC socket reader runs in a QThread — emits Qt signals to the main thread only.

## PIN Overlay (widgets/pin_overlay.py)
- Digit positions MUST be randomized on every show() call: random.shuffle(digit_list)
- Render digits as QLabel with text '●' — never display the actual digit
- Long-press detection: QTimer(3000ms) started on touchDown in the IDLE reserved region
- Lockout state persisted to events DB; check via IPC before allowing entry attempt
- Operator functions only: last scan summary, health status, language, operator_hold ack

## operator_hold (OPERATOR_HOLD state)
- Only available after CLEAN or SUSPICIOUS verdict (never THREAT)
- Entered when config.operator_hold.enabled=true and scan completes
- Display: PIN entry required + countdown timer showing remaining hold seconds
- On timeout: auto-transition to EJECTING (no operator action)
- On PIN accepted: operator may view result summary and acknowledge → EJECTING
- Log entry on OPERATOR_HOLD enter and exit (reason: acknowledged | timeout | removed)

## Touchscreen
Minimum tap target: 48×48px. Use QTouchEvent, not mouse events.
