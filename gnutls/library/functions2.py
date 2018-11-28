
from ctypes import c_void_p
from gnutls.library import __libgnutls, _libgnutls
from gnutls.library.callbacks import gnutls_pin_function_cb

gnutls_free = __libgnutls._libgnutls_free
gnutls_free.argtypes = [c_void_p]
gnutls_free.restype = None

_libgnutls.pkcs11_set_pin_function(gnutls_pin_function_cb)
