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

#if PY_MAJOR_VERSION == 3
static struct PyModuleDef _libgnutls_module = {
    PyModuleDef_HEAD_INIT,
    "pygnutls",
    NULL,
    0,
    _libgnutlsModule_methods,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif

#if PY_MAJOR_VERSION == 3
PyMODINIT_FUNC PyInit__libgnutls(void)
#else
PyMODINIT_FUNC init_libgnutls(void)
#endif
{
#if PY_MAJOR_VERSION == 3
    PyObject *module = PyModule_Create(&_libgnutls_module);
#else
    (void) Py_InitModule("pygnutls", _libgnutlsModule_methods);
#endif

#if PY_MAJOR_VERSION == 3
    return module;
#endif
}
