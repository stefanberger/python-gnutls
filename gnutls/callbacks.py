

def gnutls_set_pin_for_keyuri(keyuri, pin):
    from gnutls.library.callbacks import _keyuri_pins
    _keyuri_pins.append((keyuri, pin))


def gnutls_remove_pin_for_keyuri(keyuri):
    from gnutls.library.callbacks import _keyuri_pins
    _keyuri_pins = [x for x in _keyuri_pins if not (x[0] == keyuri)]
