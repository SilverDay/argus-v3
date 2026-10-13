# GUI translations

English is the source language (no file needed). Other languages are
`usbscan_<locale>.ts` (source, committed) and `usbscan_<locale>.qm` (compiled,
installed to `gui.translations_dir`). Create or update with
`scripts/update-translations.sh <locale>...`; translate with `pyside6-linguist`.
The operator overlay lists every installed `.qm` (spec §4.3 "language").
