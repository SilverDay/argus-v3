#!/bin/sh
# Extract GUI strings into translations/usbscan_<lang>.ts and compile .qm files.
#   scripts/update-translations.sh de fr      # create/update German and French
# Translate the .ts files with Qt Linguist (pyside6-linguist), then re-run to compile.
# All GUI strings use context "usbscan" (QCoreApplication.translate / QT_TRANSLATE_NOOP).
set -eu
cd "$(dirname "$0")/.."
for lang in "$@"; do
    pyside6-lupdate src/gui/*.py src/gui/widgets/*.py -ts "translations/usbscan_${lang}.ts"
done
for ts in translations/usbscan_*.ts; do
    [ -e "$ts" ] || continue
    pyside6-lrelease "$ts" -qm "${ts%.ts}.qm"
done
