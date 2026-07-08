use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use scirust::attention::slha_v2::{SciRustSlhaTile, D_C, LATENT_BYTES, N_GROUPS, RESIDUAL_WORDS};
use scirust::audit;

/// Python wrapper for SciRustSlhaTile.
#[pyclass]
#[derive(Clone)]
pub struct PySlhaTile {
    pub inner: SciRustSlhaTile,
}

#[pymethods]
impl PySlhaTile {
    #[new]
    #[pyo3(signature = (latent_kv, residual_bitmap, scale, dynamic_lambda, residual_sigma, token_id, position, head_id, flags, group_scales))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        latent_kv: [u8; LATENT_BYTES],
        residual_bitmap: [u64; RESIDUAL_WORDS],
        scale: f32,
        dynamic_lambda: f32,
        residual_sigma: f32,
        token_id: u32,
        position: u32,
        head_id: u16,
        flags: u16,
        group_scales: [u8; N_GROUPS],
    ) -> Self {
        Self {
            inner: SciRustSlhaTile {
                latent_kv,
                residual_bitmap,
                scale,
                dynamic_lambda,
                residual_sigma,
                token_id,
                position,
                head_id,
                flags,
                group_scales,
            },
        }
    }

    #[getter]
    fn latent_kv<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.latent_kv)
    }

    /// Compute the score for this tile given q_coarse and q_sign.
    ///
    /// Supports zero-copy access to PyTorch/NumPy arrays via the buffer protocol.
    fn compute_score(&self, q_coarse: PyBuffer<f32>, q_sign: PyBuffer<u64>) -> PyResult<f32> {
        if q_coarse.dimensions() != 1 || q_coarse.shape()[0] != D_C {
            return Err(PyValueError::new_err(format!(
                "q_coarse must be 1D array of size {}",
                D_C
            )));
        }
        if !q_coarse.is_c_contiguous() {
            return Err(PyValueError::new_err("q_coarse must be C-contiguous"));
        }
        if q_sign.dimensions() != 1 || q_sign.shape()[0] != RESIDUAL_WORDS {
            return Err(PyValueError::new_err(format!(
                "q_sign must be 1D array of size {}",
                RESIDUAL_WORDS
            )));
        }
        if !q_sign.is_c_contiguous() {
            return Err(PyValueError::new_err("q_sign must be C-contiguous"));
        }

        // SAFETY: We checked dimensions, shape and contiguity.
        // PyBuffer ensures the memory is valid for the duration of the call.
        let q_coarse_slice =
            unsafe { std::slice::from_raw_parts(q_coarse.buf_ptr() as *const f32, D_C) };
        let q_sign_slice =
            unsafe { std::slice::from_raw_parts(q_sign.buf_ptr() as *const u64, RESIDUAL_WORDS) };

        let q_coarse_ref = q_coarse_slice.try_into().unwrap();
        let q_sign_ref = q_sign_slice.try_into().unwrap();

        Ok(self.inner.compute_score(q_coarse_ref, q_sign_ref))
    }
}

/// Run the SLHA v2 self-audit and return a JSON string.
#[pyfunction]
fn run_audit() -> String {
    audit::run().to_compact()
}

/// The slha_core Python module.
#[pymodule]
fn slha_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySlhaTile>()?;
    m.add_function(wrap_pyfunction!(run_audit, m)?)?;
    m.add("D_C", D_C)?;
    m.add("D_S", scirust::attention::slha_v2::D_S)?;
    Ok(())
}
