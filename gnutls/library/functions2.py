
from ctypes import c_void_p
from gnutls.library import __libgnutls

gnutls_free = __libgnutls._libgnutls_free
gnutls_free.argtypes = [c_void_p]
gnutls_free.restype = None

