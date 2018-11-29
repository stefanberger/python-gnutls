
def gnutls_set_pin_for_keyuri(keyuri, pin):
    from gnutls.library.callbacks import _keyuri_pins
    _keyuri_pins.append((keyuri, pin))


def gnutls_remove_pin_for_keyuri(keyuri):
    from gnutls.library.callbacks import _keyuri_pins
    _keyuri_pins = [x for x in _keyuri_pins if not (x[0] == keyuri)]


def gnutls_register_pin_for_keyuri_callback(cb, data):
    from gnutls.library.callbacks import _keyuri_cbs
    _keyuri_cbs.append((cb, data))


def gnutls_deregister_pin_for_keyuri_callback(cb):
    from gnutls.library.callbacks import _keyuri_cbs
    _keyuri_cbs = [x for x in _keyuri_cbs if not (x[0] == cb)]
