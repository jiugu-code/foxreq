use pyo3::{create_exception, exceptions::PyException, prelude::*};

use crate::worker::NativeFailure;

create_exception!(
    _foxreq,
    NativeError,
    PyException,
    "A structured error raised by the foxreq native worker."
);

pub(crate) fn into_pyerr(py: Python<'_>, failure: NativeFailure) -> PyErr {
    let kind = failure.kind().as_str();
    let message = failure.message().to_owned();
    let error = NativeError::new_err(message.clone());
    let value = error.value(py);
    if let Err(attribute_error) = value.setattr("kind", kind) {
        return attribute_error;
    }
    if let Err(attribute_error) = value.setattr("message", message) {
        return attribute_error;
    }
    error
}
