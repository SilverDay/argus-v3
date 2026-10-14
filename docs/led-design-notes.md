# Status LED — Design Notes (Phase 6)

## Decisions

- **Native `lgpio`, not `rpi-lgpio`.** The plan names "lgpio (via rpi-lgpio)". Verified from
  the rpi-lgpio 0.6 source: it is "A compatibility shim between RPi.GPIO and lgpio" and
  installs a package named `RPi.GPIO`, which the project rules exclude. The service uses
  the `lgpio` module from the Trixie package `python3-lgpio` (venv with
  `--system-site-packages`); `rpi-lgpio` was removed from requirements.txt.
- **Direct subscription to the orchestrator state socket** (no `led.sock`, no GUI bridge):
  a GUI crash cannot freeze the light. Orchestrator unreachable → NOT_READY (white solid).
- **Software PWM** with `lgpio.tx_pwm` (0.1–10000 Hz, duty 0–100 %, per lgpio docs). With
  infinite cycles a new setting replaces the old one at the end of the current cycle;
  the driver only issues commands when a duty changes (25 fps max), so the PWM queue
  cannot fill.
- **Driver selection:** `led.driver: lgpio` in production — failure to open the GPIO chip
  is fatal and visible; `auto` falls back to a stub for development.

## Patterns (spec §3.3; plan Phase 6 for non-verdict states)

| State / verdict | Pattern |
|---|---|
| CLEAN | green solid |
| THREAT | red pulse 4 Hz |
| SUSPICIOUS | amber pulse 2 Hz |
| INCOMPLETE | white/amber alternate 1 Hz |
| ERROR | white blink 2 Hz |
| REJECTED | white/amber alternate 2 Hz |
| NOT_READY, STARTING, EJECTING, orchestrator unreachable | white solid |
| IDLE | blue pulse 1 Hz |
| VALIDATING, MOUNTING, SCANNING, EVALUATING | amber solid |
| RESULT, OPERATOR_HOLD | pattern of the verdict |
| EJECT_FAILED (not in spec) | red/white alternate 2 Hz — distinct from every verdict |

Open: NOT_READY and EJECTING share "white solid" (as in the plan); EJECTING lasts seconds.

## Wiring

Pins, resistor values, common-anode variant and the `python -m src.led --test` wiring check:
docs/hardware-wiring.md.

## To validate on the Pi

- GPIO chip number for the 40-pin header on the Trixie kernel (`gpiodetect`; config
  `led.gpiochip`, default 0) and the device in the systemd draft.
- Colour balance of the chosen LED (amber = R 100 % / G 35 %), resistor values, brightness.
- `lgpio` software-PWM flicker at 200 Hz.
