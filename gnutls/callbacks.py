
from gnutls.library.callbacks import _keyuri_pins

def gnutls_set_pin_for_keyuri(keyuri, pin):
    global _keyuri_pins
    _keyuri_pins.append((keyuri, pin))

def gnutls_remove_pin_for_keyuri(keyuri):
    global _keyuri_pins
    _keyuri_pins = [x for x in _keyuri_pins if not (x[0] == keyuri)]
