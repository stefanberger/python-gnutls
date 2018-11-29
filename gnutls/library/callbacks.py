
import os
from gnutls.library.constants import GNUTLS_PIN_USER, GNUTLS_PIN_WRONG

_keyuri_pins = []
_keyuri_cbs = []

def gnutls_pin_function_cb(attempts, token_url, token_label, flags):
    global _keyuri_pins
    global _keyuri_cbs

    # Process application callbacks
    for cb, data in _keyuri_cbs:
        pin, ret = cb(attempt, token_url, token_label, flags, data)
        if pin:
            return pin, 0

    if (flags & GNUTLS_PIN_WRONG) != 0:
        return None, -1

    pin = None
    for keyuri, _pin in _keyuri_pins:
        if keyuri.find(token_url) == 0:
            pin = _pin
            break
    if pin:
        return pin, 0

    return None, -1
