use std::{fs::File, io::{BufRead, BufReader}, path::PathBuf};

use regex::Regex;

use crate::panickiller::{database::model::LocInfo, utils::{select_dep, select_loc_info, select_loc_info_by_id}};
use super::rank::RankList;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FaultLoc {
    pub ident: String,
    pub line_num: usize,
    pub col_num: usize,
    pub file_path: PathBuf,
    pub is_dep: bool,
    pub depth: i32,
    pub score: f64,
}

impl FaultLoc {
    pub fn new(loc_info: LocInfo, is_dep: bool, depth: i32) -> Self {
        FaultLoc {
            ident: loc_info.ident,
            line_num: loc_info.line_num as usize,
            col_num: loc_info.col_num as usize,
            file_path: PathBuf::from(&loc_info.file_path),
            is_dep,
            depth,
            score: 0.0,
        }
    }
}

pub fn find_dependencies(lhs: FaultLoc) -> Vec<FaultLoc> {
    let lhs_loc = select_loc_info(lhs.file_path.display().to_string(), lhs.line_num as i32, lhs.col_num as i32);
    let mut dependencies = Vec::new();

    // println!("lhs_loc: {:?}", lhs_loc);

    if lhs_loc.is_none() {
        return dependencies;
    }

    let deps = select_dep(&lhs_loc.unwrap());
    for dep in deps {
        let rhs_loc = select_loc_info_by_id(dep.rhs_id);
        let rhs_dep = FaultLoc::new(rhs_loc, true, lhs.depth);
        // println!("lhs.depth: {}, rhs_dep: {:?}", lhs.depth, rhs_dep);
        dependencies.push(rhs_dep);
    }

    dependencies
}

pub fn extract_backtrace(path: PathBuf) -> Vec<FaultLoc> {
    let re_line1 = Regex::new(r"(\d+):\s+0x[0-9a-f]+ - (.+?)::(.+?)$").unwrap();
    let re_line2 = Regex::new(r"^\s*at (/.+?):(\d+):(\d+)").unwrap();
    let file = File::open(path).expect("Failed to open backtrace file!");
    let reader = BufReader::new(file);
    let mut fault_locs: Vec<FaultLoc> = Vec::new();

    let mut lines = reader.lines();
    while let Some(Ok(line1)) = lines.next() {
        if let Some(caps) = re_line1.captures(&line1) {
            let depth = caps[1].parse::<i32>().unwrap();
            let full_ident = caps[3].to_string();
            let ident_parts: Vec<&str> = full_ident.split("::").collect();
            let ident = if let Some(first_part) = ident_parts.first() {
                first_part.to_string()
            } else {
                full_ident
            };

            if let Some(Ok(line2)) = lines.next() {
                if let Some(caps) = re_line2.captures(&line2) {
                    let mut file_path = PathBuf::from(&caps[1]);

                    let re_src = Regex::new(r"lib-.+?/.+?/.+?/(?P<src_content>.+)$").unwrap();
                    if let Some(caps) = re_src.captures(&file_path.display().to_string()) {
                        file_path = PathBuf::from(&caps["src_content"]);
                    }

                    if file_path.display().to_string().contains("/rustc") 
                        || file_path.display().to_string().contains("/.cargo") 
                        || file_path.display().to_string().contains("main.rs") {
                        continue;
                    }

                    // let file_path_str = file_path.display().to_string();
                    // if let Some(src_index) = file_path_str.find("src/") {
                    //     let trimmed_path = &file_path_str[src_index..];
                    //     file_path = PathBuf::from(trimmed_path);
                    // }

                    let line_num = caps[2].parse::<usize>().unwrap_or(0);
                    let col_num = caps[3].parse::<usize>().unwrap_or(0) - 1;
                    let is_dep = false;

                    let lhs = FaultLoc {
                        ident,
                        line_num,
                        col_num,
                        file_path,
                        is_dep,
                        depth,
                        score: 0.0,
                    };
                    fault_locs.push(lhs.clone());

                    let mut dependencies = find_dependencies(lhs.clone());
                    if !dependencies.is_empty() {
                        fault_locs.append(&mut dependencies);
                    }
                }
            }
        }
    }

    let mut rk_list = RankList::new(fault_locs);
    rk_list.rank()
}
