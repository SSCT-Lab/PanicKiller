use std::path::PathBuf;
use rustc_data_structures::fx::FxHashMap;

use super::extract::FaultLoc;

pub struct RankList {
    pub rk_list: Vec<FaultLoc>
}

impl RankList {
    pub fn new(fault_locs: Vec<FaultLoc>) -> Self {
        RankList {
            rk_list: fault_locs
        }
    }

    fn tune_depth(&mut self) {
        self.rk_list.sort_by_key(|fault_loc| fault_loc.depth);

        let mut cur_depth = 0;
        for fault_loc in &mut self.rk_list {
            if !fault_loc.is_dep {
                cur_depth += 1;
            }
            fault_loc.depth = cur_depth as i32;
        }
    }

    pub fn rank(&mut self) -> Vec<FaultLoc> {
        self.tune_depth();

        let mut file_path_counts: FxHashMap<&PathBuf, usize> = FxHashMap::default();
        for fault_loc in &self.rk_list {
            let count = file_path_counts.entry(&fault_loc.file_path).or_insert(0);
            *count += 1;
        }

        let mut res = self.rk_list.clone();
        for fault_loc in &mut res {
            let count = file_path_counts.get(&fault_loc.file_path).unwrap();
            fault_loc.score = *count as f64 / fault_loc.depth as f64;

            if fault_loc.is_dep {
                fault_loc.score *= 0.5;
            }
        }
        res.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        
        res
    }
}