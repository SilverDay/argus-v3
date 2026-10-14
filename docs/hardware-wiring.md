# Hardware wiring: status LED

The station shows its state on one discrete RGB LED (spec §5.1). It is a common-cathode LED
by default, driven by three GPIOs of the Raspberry Pi 5 40-pin header (J8) through series
resistors. Patterns per state: docs/led-design-notes.md.

## Pin assignment

| LED lead | GPIO (BCM) | Header pin (physical) | Config key |
|---|---|---|---|
| Red anode | GPIO 17 | **pin 11** | `led.pin_red: 17` |
| Green anode | GPIO 27 | **pin 13** | `led.pin_green: 27` |
| Blue anode | GPIO 22 | **pin 15** | `led.pin_blue: 22` |
| Common cathode | GND | **pin 14** (any GND pin works: 6, 9, 14, 20, 25, 30, 34, 39) | – |

- **Source.** The mapping is the standard 40-pin header layout, as listed for the Pi 4 and
  Pi 5 in the gpiozero pin database. Physical pin 1 (3.3 V) has the square solder pad. If
  gpiozero is installed, `pinout` prints the layout for the actual board.
- **Geometry.** Pins 11, 13 and 15 are consecutive in the odd-numbered row. Pin 14 (GND) is
  in the even row, directly opposite pin 13.
- **Config.** The config keys use BCM GPIO numbers, not physical pin numbers.

```
 Pi 5 header J8 (excerpt)                  RGB LED, common cathode

  pin 11  GPIO17 ──[ R_red   ]────────────►|── red anode   ─┐
  pin 13  GPIO27 ──[ R_green ]────────────►|── green anode ─┼── common cathode (longest lead)
  pin 15  GPIO22 ──[ R_blue  ]────────────►|── blue anode  ─┘          │
  pin 14  GND    ───────────────────────────────────────────────────────┘
```

**One resistor per colour, on the anode side.** Never connect an LED to a GPIO without a
series resistor, and never feed the LED from the 5 V pins. The Raspberry Pi documentation
warns about both.

## Resistor values

The GPIOs drive 3.3 V. Per channel:

```
R = (3.3 V − V_f) / I_LED          V_f = forward voltage of that colour (LED datasheet)
```

- **Current per channel.** Keep it at **about 4 mA or less**.
  - The Raspberry Pi GPIO documentation gives default drive strengths of 8 mA (BCM2835-based
    boards) and 4 mA (BCM2711, Pi 4). It publishes no equivalent table for the Pi 5's RP1.
  - So the conservative 4 mA figure is used. For a modern indicator LED it is plenty bright.
- **Typical values.** Check them against your LED's datasheet.

| Channel | Typical V_f | Example for ≈ 4 mA |
|---|---|---|
| Red | ≈ 2.0 V | (3.3 − 2.0) / 0.004 ≈ 325 Ω → **330 Ω** |
| Green / blue (InGaN) | ≈ 2.8–3.1 V | (3.3 − 2.9) / 0.004 ≈ 100 Ω → **100 Ω**, then adjust |

- **Green/blue headroom is small.** These colours have a forward voltage close to 3.3 V, so
  their brightness varies between parts. Pick an LED whose datasheet gives V_f ≤ 3.0 V at a
  few mA.
- **Need more brightness?** Drive each colour through a transistor or a MOSFET stage from an
  external supply, instead of raising the GPIO current.
- **Colour balance.** Adjust it by resistor value first, then with
  `led.brightness_percent`. "Amber" is a software mix (red 100 %, green 35 %, so it depends on
  the balance; check it visually).

## Common-anode LEDs

A common-anode LED also works:
1. Connect its common lead to **3.3 V (pin 1 or 17)**. Never to 5 V: a 5 V common anode would
   push current into the GPIO pins.
2. Keep the series resistors on the three colour leads.
3. Set `led.common_anode: true`. The driver then inverts the outputs: GPIO low = on.

## GPIO chip

lgpio opens `/dev/gpiochip<led.gpiochip>` (default `0`). Before relying on the default,
check on the station which chip carries the 40-pin header:

```
gpiodetect                      # lists the GPIO chips
gpioinfo gpiochip0 | grep -E '"GPIO(17|22|27)"'   # the header chip names its lines GPIO17 ...
```

- If the header is on another chip number, set `led.gpiochip` accordingly.
- The LED unit allows `/dev/gpiochip0` and `/dev/gpiochip4`. The chip number has changed
  between kernel versions, and this could not be checked offline (led-design-notes.md).

## Wiring check

The LED service must be stopped while the check holds the GPIOs:

```
sudo systemctl stop usb-scan-led
cd /opt/usb-scan && sudo .venv/bin/python -m src.led --test
sudo systemctl start usb-scan-led
```

The LED shows **red, green, blue, white** for two seconds each, then switches off.
- **Wrong colour:** two leads are swapped.
- **A colour missing:** check its resistor and lead.
- **Inverted (lit when it should be off):** set `led.common_anode`.
- **"WARNING: stub driver":** set `led.driver: lgpio` (production setting).

Once the service runs, the IDLE state shows a slow **blue pulse**.

## Not wired by this software

Spec §5.1 also lists an optional buzzer (GPIO 18, pin 12) and an enclosure tamper switch
(GPIO 24, pin 18). Neither is implemented in this release. Leave those pins free so they
stay available.
