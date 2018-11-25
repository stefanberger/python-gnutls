#include <Python.h>
#include <gnutls/gnutls.h>

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

static PyObject *libgnutls_init(PyObject *self, PyObject *args)
{
    return Py_BuildValue("");
}

static PyMethodDef _libgnutlsModule_methods[] = {
    {"init", libgnutls_init, METH_VARARGS},
    {"gnutls_free", libgnutls_free, METH_VARARGS},
    {NULL, NULL, 0}
};

PyMODINIT_FUNC init_libgnutls(void)
{
    (void) Py_InitModule("_libgnutls", _libgnutlsModule_methods);
}
