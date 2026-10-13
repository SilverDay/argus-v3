"""Display texts, colours and icons per state/verdict (spec §3.3, §4.1, §4.2).

Every state is shown with colour AND an icon AND text (never colour alone). Texts are
the user instructions from the spec's verdict table, kept short for a 5" screen.
All strings go through ``tr`` so they can be translated (.ts/.qm, spec §4.1).
"""
from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QT_TRANSLATE_NOOP, QCoreApplication

CONTEXT = "usbscan"


def tr(text: str) -> str:
    """Translate a string at runtime. Table strings are marked with QT_TRANSLATE_NOOP; Literals in code must use
    QCoreApplication.translate("usbscan", "...") so pyside6-lupdate extracts them."""
    return QCoreApplication.translate(CONTEXT, text)


@dataclass(frozen=True)
class Look:
    background: str
    foreground: str
    icon: str          # check | cross | warn | question | info | block | spinner | hand | usb
    title: str
    message: str


# Dark backgrounds with white text: contrast ratios well above WCAG AA for large text.
VERDICTS: dict[str, Look] = {
    "CLEAN": Look("#1b5e20", "#ffffff", "check", QT_TRANSLATE_NOOP("usbscan", "No known threats detected"),
                  QT_TRANSLATE_NOOP("usbscan", "This does not guarantee the device is safe.")),
    "THREAT": Look("#b71c1c", "#ffffff", "cross", QT_TRANSLATE_NOOP("usbscan", "Threat detected"),
                   QT_TRANSLATE_NOOP("usbscan", "Do not use this device. Contact IT.")),
    "SUSPICIOUS": Look("#8a4b00", "#ffffff", "warn", QT_TRANSLATE_NOOP("usbscan", "Suspicious content"),
                       QT_TRANSLATE_NOOP("usbscan", "Contact IT before using this device.")),
    "INCOMPLETE": Look("#5d4037", "#ffffff", "question", QT_TRANSLATE_NOOP("usbscan", "Not fully checked"),
                       QT_TRANSLATE_NOOP("usbscan", "The device could not be fully assessed. Contact IT.")),
    "ERROR": Look("#37474f", "#ffffff", "cross", QT_TRANSLATE_NOOP("usbscan", "Scan error"),
                  QT_TRANSLATE_NOOP("usbscan", "Contact IT. Follow the removal instructions.")),
    "REJECTED": Look("#4a148c", "#ffffff", "block", QT_TRANSLATE_NOOP("usbscan", "Device not accepted"),
                     QT_TRANSLATE_NOOP("usbscan", "This device is not allowed. Contact IT.")),
    "NOT_READY": Look("#263238", "#ffffff", "info", QT_TRANSLATE_NOOP("usbscan", "Scanning unavailable"),
                      QT_TRANSLATE_NOOP("usbscan", "The station is not ready. Contact IT.")),
}

STATES: dict[str, Look] = {
    "STARTING": Look("#263238", "#ffffff", "spinner", QT_TRANSLATE_NOOP("usbscan", "Starting"), QT_TRANSLATE_NOOP("usbscan", "Checking the station…")),
    "NOT_READY": VERDICTS["NOT_READY"],
    "IDLE": Look("#0d47a1", "#ffffff", "usb", QT_TRANSLATE_NOOP("usbscan", "Insert a USB device"), QT_TRANSLATE_NOOP("usbscan", "The check starts automatically.")),
    "VALIDATING": Look("#0d47a1", "#ffffff", "spinner", QT_TRANSLATE_NOOP("usbscan", "Checking device"), QT_TRANSLATE_NOOP("usbscan", "Please wait. Do not remove the device.")),
    "MOUNTING": Look("#0d47a1", "#ffffff", "spinner", QT_TRANSLATE_NOOP("usbscan", "Preparing device"), QT_TRANSLATE_NOOP("usbscan", "Please wait. Do not remove the device.")),
    "SCANNING": Look("#0d47a1", "#ffffff", "spinner", QT_TRANSLATE_NOOP("usbscan", "Scanning"), QT_TRANSLATE_NOOP("usbscan", "Please wait. Do not remove the device.")),
    "EVALUATING": Look("#0d47a1", "#ffffff", "spinner", QT_TRANSLATE_NOOP("usbscan", "Evaluating"), QT_TRANSLATE_NOOP("usbscan", "Please wait. Do not remove the device.")),
    "OPERATOR_HOLD": Look("#004d40", "#ffffff", "hand", QT_TRANSLATE_NOOP("usbscan", "Result on hold"),
                          QT_TRANSLATE_NOOP("usbscan", "An operator may review the result.")),
    "EJECTING": Look("#0d47a1", "#ffffff", "spinner", QT_TRANSLATE_NOOP("usbscan", "Ejecting"), QT_TRANSLATE_NOOP("usbscan", "Do not remove the device yet.")),
    "RESULT": Look("#263238", "#ffffff", "info", QT_TRANSLATE_NOOP("usbscan", "Result"), ""),
    "EJECT_FAILED": Look("#b71c1c", "#ffffff", "warn", QT_TRANSLATE_NOOP("usbscan", "Device not safely ejected"),
                         QT_TRANSLATE_NOOP("usbscan", "Do not remove the device. Contact IT.")),
    "REJECTED": VERDICTS["REJECTED"],
    "ERROR": VERDICTS["ERROR"],
}

DISCONNECTED = Look("#263238", "#ffffff", "info", QT_TRANSLATE_NOOP("usbscan", "Scanning unavailable"),
                    QT_TRANSLATE_NOOP("usbscan", "The station is not ready. Contact IT."))

REMOVAL_TEXT = {
    "safe": QT_TRANSLATE_NOOP("usbscan", "You can now remove the device."),
    "unsafe": QT_TRANSLATE_NOOP("usbscan", "Do not remove the device yet."),
    "removed": QT_TRANSLATE_NOOP("usbscan", "The device was removed before the check finished."),
}

REJECT_REASONS = {
    "usb_policy_blocked": QT_TRANSLATE_NOOP("usbscan", "Blocked by the USB device policy."),
    "hid_interface": QT_TRANSLATE_NOOP("usbscan", "The device also acts as a keyboard or mouse."),
    "non_storage_interface": QT_TRANSLATE_NOOP("usbscan", "The device is not a plain storage device."),
    "hub_not_allowed": QT_TRANSLATE_NOOP("usbscan", "USB hubs are not allowed."),
    "no_storage_device": QT_TRANSLATE_NOOP("usbscan", "No storage was found on the device."),
    "capacity_exceeded": QT_TRANSLATE_NOOP("usbscan", "The device is larger than allowed."),
    "second_device": QT_TRANSLATE_NOOP("usbscan", "Only one device at a time."),
}


def verdict_look(verdict: str | None) -> Look:
    return VERDICTS.get(verdict or "", VERDICTS["ERROR"])


def state_look(state: str) -> Look:
    return STATES[state]
