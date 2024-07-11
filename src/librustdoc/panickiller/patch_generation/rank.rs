use pyo3::prelude::*;
use super::patch::Patch;

pub(crate) struct PatchRanker {
    pub patches: Vec<Patch>,
}

impl PatchRanker {
    pub fn new(patches: Vec<Patch>) -> Self {
        PatchRanker { patches }
    }

    pub fn rank_patches(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            let sys = PyModule::import(py, "sys")?;
            let path = "/home/yunboni/PanicKiller/src/librustdoc/panickiller/patch_generation";
            sys.getattr("path")?.call_method1("append", (path,))?;

            let text_similarity = PyModule::import(py, "text_similarity")?;

            for patch in &mut self.patches {
                let score: f64 = text_similarity.call_method1(
                    "calculate_similarity_for_single_pair",
                    (patch.panic_info.clone(), patch.fix_pattern.to_string())
                )?.extract()?;

                patch.score += score;
            }

            self.patches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

            Ok(())
        })
    }
}
