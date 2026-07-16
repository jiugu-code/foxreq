mod error;
mod worker;

use std::path::PathBuf;

use pyo3::{
    prelude::*,
    types::{PyBytes, PyList},
};

use error::{into_pyerr, NativeError};
use worker::{NativeRequest, NativeResponseData, WorkerHandle};

#[pyclass(module = "foxreq._foxreq")]
struct NativeSession {
    worker: WorkerHandle,
    profile_id: String,
}

#[pymethods]
impl NativeSession {
    #[new]
    fn new(
        runtime_dir: String,
        trust_anchors_der: Vec<Vec<u8>>,
        profile_id: String,
    ) -> PyResult<Self> {
        if !matches!(profile_id.as_str(), "firefox_140_esr" | "firefox_152") {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "invalid TLS profile",
            ));
        }
        let worker = WorkerHandle::spawn(
            PathBuf::from(runtime_dir),
            trust_anchors_der,
            profile_id.clone(),
            16,
        )
        .map_err(|failure| Python::attach(|py| into_pyerr(py, failure)))?;
        Ok(Self { worker, profile_id })
    }

    #[pyo3(signature = (method, url, headers, body, timeout_seconds, insecure = false))]
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        py: Python<'_>,
        method: Vec<u8>,
        url: String,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        body: Vec<u8>,
        timeout_seconds: f64,
        insecure: bool,
    ) -> PyResult<NativeResponse> {
        let request = NativeRequest {
            method,
            url,
            headers,
            body,
            timeout_seconds,
            insecure,
            profile_id: self.profile_id.clone(),
        };
        let response = py
            .detach(|| self.worker.request(request))
            .map_err(|failure| into_pyerr(py, failure))?;
        Ok(response.into())
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.worker.close())
            .map_err(|failure| into_pyerr(py, failure))
    }
}

#[pyclass(module = "foxreq._foxreq")]
struct NativeHttpSession {
    worker: WorkerHandle,
    profile_id: String,
}

#[pymethods]
impl NativeHttpSession {
    #[new]
    fn new(profile_id: String) -> PyResult<Self> {
        if !matches!(profile_id.as_str(), "firefox_140_esr" | "firefox_152") {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "invalid Firefox profile",
            ));
        }
        let worker = WorkerHandle::spawn_plain()
            .map_err(|failure| Python::attach(|py| into_pyerr(py, failure)))?;
        Ok(Self { worker, profile_id })
    }

    #[pyo3(signature = (method, url, headers, body, timeout_seconds, insecure = false))]
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        py: Python<'_>,
        method: Vec<u8>,
        url: String,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        body: Vec<u8>,
        timeout_seconds: f64,
        insecure: bool,
    ) -> PyResult<NativeResponse> {
        let _ = insecure;
        let request = NativeRequest {
            method,
            url,
            headers,
            body,
            timeout_seconds,
            insecure: false,
            profile_id: self.profile_id.clone(),
        };
        let response = py
            .detach(|| self.worker.request(request))
            .map_err(|failure| into_pyerr(py, failure))?;
        Ok(response.into())
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.worker.close())
            .map_err(|failure| into_pyerr(py, failure))
    }
}

#[pyclass(module = "foxreq._foxreq", frozen)]
struct NativeResponse {
    status: u16,
    reason: Vec<u8>,
    url: String,
    version: String,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

impl From<NativeResponseData> for NativeResponse {
    fn from(response: NativeResponseData) -> Self {
        Self {
            status: response.status,
            reason: response.reason,
            url: response.url,
            version: response.version,
            headers: response.headers,
            body: response.body,
        }
    }
}

#[pymethods]
impl NativeResponse {
    #[getter]
    const fn status(&self) -> u16 {
        self.status
    }

    #[getter]
    fn reason(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.reason).unbind()
    }

    #[getter]
    fn url(&self) -> &str {
        &self.url
    }

    #[getter]
    fn version(&self) -> &str {
        &self.version
    }

    #[getter]
    fn headers(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let headers = PyList::empty(py);
        for (name, value) in &self.headers {
            headers.append((PyBytes::new(py, name), PyBytes::new(py, value)))?;
        }
        Ok(headers.into_any().unbind())
    }

    #[getter]
    fn body(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.body).unbind()
    }
}

#[pymodule]
fn _foxreq(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeHttpSession>()?;
    module.add_class::<NativeSession>()?;
    module.add_class::<NativeResponse>()?;
    module.add("NativeError", module.py().get_type::<NativeError>())?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pyo3::Python;

    use super::NativeHttpSession;

    #[test]
    fn native_http_session_accepts_exact_profiles() {
        Python::initialize();
        Python::attach(|_| {
            let first = NativeHttpSession::new("firefox_140_esr".to_owned());
            let second = NativeHttpSession::new("firefox_152".to_owned());
            assert!(first.is_ok());
            assert!(second.is_ok());
            first.unwrap().worker.close().unwrap();
            second.unwrap().worker.close().unwrap();
        });
    }

    #[test]
    fn native_http_session_rejects_unknown_profiles() {
        Python::initialize();
        Python::attach(|_| {
            assert!(NativeHttpSession::new("firefox_latest".to_owned()).is_err());
        });
    }
}
