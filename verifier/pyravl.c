// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <string.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <ravl/capi.h>

static PyObject* py_verify_attestation_json(PyObject* self, PyObject* args)
{
  const char* attestation;

  if (!PyArg_ParseTuple(args, "s", &attestation))
    return NULL;

  ravl_options_t options = {.verbosity = 2, .fresh_endorsements = 0};

  ravl_status_t r =
    verify_attestation_json(attestation, strlen(attestation), &options);

  if (r != RAVL_OK && last_exception_message)
    printf("%s\n", last_exception_message);

  return r == RAVL_OK ? Py_True : Py_False;
}

static PyObject* py_verify_attestation_cbor(PyObject* self, PyObject* args)
{
  const uint8_t* attestation;
  Py_ssize_t size;

  if (!PyArg_ParseTuple(args, "y#", &attestation, &size))
    return NULL;

  ravl_options_t options = {.verbosity = 2, .fresh_endorsements = 1};

  ravl_status_t r = verify_attestation_cbor(attestation, size, &options);

  if (r != RAVL_OK && last_exception_message)
    printf("%s\n", last_exception_message);

  return r == RAVL_OK ? Py_True : Py_False;
}

static PyMethodDef ravl_methods[] = {
  {"verify_attestation_json",
   py_verify_attestation_json,
   METH_VARARGS,
   "Verify a JSON-encoded attestation."},
  {"verify_attestation_cbor",
   py_verify_attestation_cbor,
   METH_VARARGS,
   "Verify a CBOR-encoded attestation."},
  {NULL, NULL, 0, NULL}};

static struct PyModuleDef ravl_module = {
  PyModuleDef_HEAD_INIT, "ravl", NULL, -1, ravl_methods};

PyObject* PyInit_ravl(void)
{
  return PyModule_Create(&ravl_module);
}
