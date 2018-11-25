#include <Python.h>
#include <gnutls/gnutls.h>

#ifdef __CYGWIN__
# ifdef __EXPORT
#  undef __EXPORT
# endif
# define __EXPORT __declspec(dllexport)
#else
# define __EXPORT
#endif

__EXPORT void _libgnutls_free(void *ptr) {
    gnutls_free(ptr);
}

static PyObject *_libgnutls_init(PyObject *self, PyObject *args)
{
    return Py_BuildValue("");
}

static PyMethodDef _libgnutlsModule_methods[] = {
    {"init", _libgnutls_init, METH_VARARGS},
    {NULL, NULL, 0}
};

PyMODINIT_FUNC init_libgnutls(void)
{
    (void) Py_InitModule("_libgnutls", _libgnutlsModule_methods);
}
