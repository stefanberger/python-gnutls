#include <Python.h>
#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>

static PyObject *pkcs11_pin_function_cb = NULL;

static PyObject *libgnutls_free(PyObject *self, PyObject *args)
{
    int succ;
    void *ptr;

    if (PyTuple_Size(args) != 1) {
        PyErr_SetString(PyExc_TypeError, "gnutls_free: Need 1 parameter");
        return NULL;
    }

    succ = PyArg_ParseTuple(args, "k", &ptr);
    if (!succ)
        return NULL;

    gnutls_free(*(void **)ptr);

    return Py_BuildValue("");
}

static int libgnutls_pin_callback(void *userdata,
                                  int attempt,
                                  const char *token_url,
                                  const char *token_label,
                                  unsigned int flags,
                                  char *pin, size_t pin_max)
{
    char *envpin = NULL;
    PyObject *arglist;
    PyObject *result;
    PyGILState_STATE gstate;
    int ret;
    int succ;

    if (!pkcs11_pin_function_cb)
        return -1;

    arglist = Py_BuildValue("issi", attempt, token_url, token_label, flags);
    if (!arglist)
        return -1;

    gstate = PyGILState_Ensure();

    result = PyEval_CallObject(pkcs11_pin_function_cb, arglist);
    Py_XDECREF(arglist);

    if (!result || PyTuple_Size(result) != 2) {
        PyErr_SetString(PyExc_TypeError, "pkcs11 pin callback: need 2 return parameters");
        ret = -1;
        goto err_exit;
    }

    succ = PyArg_ParseTuple(result, "zi", &envpin, &ret);
    if (succ && !ret && envpin)
        strncpy(pin, envpin, pin_max - 1);

err_exit:
    Py_XDECREF(result);
    PyGILState_Release(gstate);

    return ret;
}

static PyObject *libgnutls_pkcs11_set_pin_function(PyObject *dummy,
                                                   PyObject *args)
{
    PyObject *result = NULL;
    PyObject *temp = NULL;

    if (PyArg_ParseTuple(args, "O:pkcs11_set_pin_function", &temp)) {
        if (!PyCallable_Check(temp)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }
        Py_XINCREF(temp);
        Py_XDECREF(pkcs11_pin_function_cb);
        pkcs11_pin_function_cb = temp;
        Py_INCREF(Py_None);
        result = Py_None;
    }
    return result;
}

static PyObject *libgnutls_init(PyObject *self, PyObject *args)
{
    gnutls_pkcs11_set_pin_function(libgnutls_pin_callback, NULL);

    return Py_BuildValue("");
}

static PyMethodDef libgnutlsModule_methods[] = {
    {"init", libgnutls_init, METH_VARARGS},
    {"gnutls_free", libgnutls_free, METH_VARARGS},
    {"pkcs11_set_pin_function", libgnutls_pkcs11_set_pin_function,
                                METH_VARARGS},
    {NULL, NULL, 0}
};

#if PY_MAJOR_VERSION == 3
static struct PyModuleDef libgnutls_module = {
    PyModuleDef_HEAD_INIT,
    "pygnutls",
    NULL,
    0,
    libgnutlsModule_methods,
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
    PyObject *module = PyModule_Create(&libgnutls_module);
#else
    (void) Py_InitModule("_libgnutls", libgnutlsModule_methods);
#endif

#if PY_MAJOR_VERSION == 3
    return module;
#endif
}
