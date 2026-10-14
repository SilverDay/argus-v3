# GUI translations

Shipped (owner decision, spec 1.5.8): English (source) and German (`usbscan_de`). The
compiled `.qm` files are committed, so the station needs no Qt tools; regenerate them after
every GUI text change (`tests/unit/gui/test_translations.py` fails if a `.ts` is out of date).

English is the source language (no file needed). Other languages are
`usbscan_<locale>.ts` (source, committed) and `usbscan_<locale>.qm` (compiled,
installed to `gui.translations_dir`). Create or update with
`scripts/update-translations.sh <locale>...`; translate with `pyside6-linguist`.
The operator overlay lists every installed `.qm` (spec §4.3 "language").
