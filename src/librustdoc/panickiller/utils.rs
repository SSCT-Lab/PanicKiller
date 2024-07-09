use std::path::PathBuf;

use regex::Regex;
use rustc_span::{FileName, FileNameDisplayPreference};
use diesel::mysql::MysqlConnection;
use super::database::model::{NewDependency, NewLocInfo,LocInfo,Dependency};
use super::database::schema::loc_info::dsl::*;
use super::database::schema::dependencies::dsl::*;
use diesel::define_sql_function;

use diesel::prelude::*;

use super::fault_localization::graph::DependencyGraph;

pub fn filename_to_pathbuf(file_name: &FileName) -> PathBuf {
    match file_name {
        FileName::Real(path) => PathBuf::from(path.to_string_lossy(FileNameDisplayPreference::Local).into_owned()),
        _ => PathBuf::new()
    }
}

pub fn get_connection() -> MysqlConnection {
    super::database::establish_connection()
}

pub fn insert_dependency_graph(graph: &DependencyGraph<'_>) {
    for (lhs, rhs_vec) in &graph.lhs_to_loc_info {
        let dep_lhs_id = insert_loc_info(NewLocInfo {
            ident: &lhs.ident,
            line_num: lhs.line_num as i32,
            col_num: lhs.col_num as i32,
            file_path: &lhs.file_path.to_string_lossy(),
        });

        for rhs in rhs_vec {
            let dep_rhs_id = insert_loc_info(NewLocInfo {
                ident: &rhs.ident,
                line_num: rhs.line_num as i32,
                col_num: rhs.col_num as i32,
                file_path: &rhs.file_path.to_string_lossy(),
            });

            insert_dependency(dep_lhs_id, dep_rhs_id);
        }
    }
}

define_sql_function! {
    #[sql_name = "LAST_INSERT_ID"]
    fn last_insert_id() -> Unsigned<Bigint>;
}

pub fn insert_loc_info(new_loc: NewLocInfo<'_>) -> i32 {
    let conn = &mut get_connection();

    diesel::insert_into(loc_info)
            .values(&new_loc)
            .execute(conn)
            .expect("Error when saving loc_info");

    let last_id: u64 = diesel::select(last_insert_id()).first(conn).expect("Error getting last insert ID");

    if last_id > i32::MAX as u64 {
        panic!("Last insert ID exceeds i32::MAX");
    }

    last_id as i32  
}

pub fn insert_dependency(dep_lhs_id: i32, dep_rhs_id: i32) {
    let conn = &mut get_connection();

    let new_dep = NewDependency {
        lhs_id: dep_lhs_id,
        rhs_id: dep_rhs_id,
    };

    diesel::insert_into(dependencies)
        .values(&new_dep)
        .execute(conn)
        .expect("Error inserting dependency");
}


pub fn select_loc_info(path: String, line: i32, _col: i32) -> Option<LocInfo> {
    let conn = &mut get_connection();

    let results = loc_info.filter(file_path.eq(path))
                        .filter(line_num.eq(line))
                        .limit(1)
                        .load::<LocInfo>(conn)
                        .expect("Failed to load LocInfo");
    
    let temp = match results.get(0) {
        Some(temp) => temp,
        None => return None,
    };

    Some(LocInfo {
        id: temp.id,
        ident: temp.ident.clone(),
        line_num: temp.line_num,
        col_num: temp.col_num,
        file_path: temp.file_path.clone(),
    })
}

pub fn select_dep(loc: &LocInfo) -> Vec<Dependency> {
    let conn = &mut get_connection();
    let results = dependencies.filter(lhs_id.eq(loc.id))
                        .load::<Dependency>(conn)
                        .expect("Failed to load LocInfo");
    results
}


pub fn select_loc_info_by_id(id_in: i32) -> LocInfo {
    use super::database::schema::loc_info::dsl::*;

    let conn = &mut get_connection();

    let results = loc_info.filter(id.eq(id_in))
                        .limit(1)
                        .load::<LocInfo>(conn)
                        .expect("Failed to load LocInfo");
    let temp = results.get(0).unwrap();

    LocInfo {
        id:temp.id,
        ident:temp.ident.clone(),
        line_num:temp.line_num,
        col_num:temp.col_num,
        file_path:temp.file_path.clone(),
    }
}

pub fn extract_index_from_panic(panic_info: String) -> Option<i32> {
    let re = Regex::new(r"index(?: is)? (\d+)").unwrap();

    if let Some(captures) = re.captures(&panic_info) {
        if let Some(index_str) = captures.get(1) {
            if let Ok(index) = index_str.as_str().parse::<i32>() {
                return Some(index);
            }
        }
    }

    None
}

// fix-baseline (perfect location)

// use super::fault_localization::extract::FaultLoc;

// pub fn get_perfect_location() -> Vec<FaultLoc> {
//     let pl_path = std::env::current_dir()
//         .expect("Failed to get current directory")
//         .parent()
//         .expect("Failed to get parent directory")
//         .join("src")
//         .join("perfect_location.txt");
//     let pl_content = std::fs::read_to_string(pl_path).expect("Failed to read perfect location file");

//     let mut fault_locs: Vec<FaultLoc> = Vec::new();

//     for line in pl_content.lines() {
//         let parts: Vec<&str> = line.split(':').collect();
//         let path = PathBuf::from(parts[0]);
//         let line = parts[1].parse::<usize>().unwrap();
//         let col = parts[2].parse::<usize>().unwrap();

//         fault_locs.push(FaultLoc {
//             ident: "".to_string(),
//             line_num: line,
//             col_num: col,
//             file_path: path,
//             is_dep: false,
//             depth: 1,
//             score: 0.0,
//         });
//     }

//     fault_locs
// }

// location-baseline1(panic)

// use super::fault_localization::extract::FaultLoc;

// pub fn extract_loc_from_panic(panic_info: String) -> Vec<FaultLoc> {
//     let re = Regex::new(r"at (.+?):(\d+):(\d+)").unwrap();
//     let re_src = Regex::new(r"lib-.+?/.+?/.+?/(?P<src_content>.+)$").unwrap();

//     let mut fault_locs: Vec<FaultLoc> = Vec::new();

//     for line in panic_info.lines() {
//         if let Some(captures) = re.captures(&line) {
//             let mut path = PathBuf::from(captures.get(1).unwrap().as_str());
//             if let Some(caps) = re_src.captures(&path.display().to_string()) {
//                 path = PathBuf::from(&caps["src_content"]);
//             }
//             let line = captures.get(2).unwrap().as_str().parse::<usize>().unwrap();
//             let col = captures.get(3).unwrap().as_str().parse::<usize>().unwrap();

//             fault_locs.push(FaultLoc {
//                 ident: "".to_string(),
//                 line_num: line,
//                 col_num: col,
//                 file_path: path,
//                 is_dep: false,
//                 depth: 1,
//                 score: 0.0,
//             });
//         }
//     }

//     fault_locs
// }

// location-baseline2(backtrace random)

// use super::fault_localization::extract::FaultLoc;
// use rand::seq::SliceRandom;

// pub fn get_random_location_from_fault_locs(mut fault_locs: Vec<FaultLoc>) -> Vec<FaultLoc> {
//     let mut rng = rand::thread_rng();
//     fault_locs.shuffle(&mut rng);
//     fault_locs.into_iter().take(5).collect()
// }

// location-baseline3(nlp)

// use pyo3::prelude::*;
// use super::fault_localization::extract::FaultLoc;

// pub fn get_fault_loc_from_simi(panic_info: String) -> PyResult<Vec<FaultLoc>> {
//     Python::with_gil(|py| {
//         let sys = PyModule::import(py, "sys")?;
//         let path = "/home/cardigan/rustc-graph/src/librustdoc/tooling/patch_generation";
//         sys.getattr("path")?.call_method1("append", (path,))?;

//         let mut all_scores: Vec<FaultLoc> = Vec::new();

//         let files = get_all_files_in_directory(&std::env::current_dir()?)?;
//         let text_similarity: &PyModule = PyModule::import(py, "text_similarity")?;
//         for file in files {
//             let file_content = std::fs::read_to_string(&file)?;
//             for (line_number, line) in file_content.lines().enumerate() {
//                 let score: f64 = text_similarity.call_method1(
//                     "calculate_similarity_for_single_pair",
//                     (panic_info.clone(), line.to_string())
//                 )?.extract()?;
                
//                 all_scores.push(FaultLoc {
//                     ident: "".to_string(),
//                     line_num: line_number + 1,
//                     col_num: 0,
//                     file_path: file.clone(),
//                     is_dep: false,
//                     depth: 1,
//                     score: score,
//                 });
//             }
//         }

//         all_scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
//         let top_scores = all_scores.into_iter().take(5).collect::<Vec<FaultLoc>>();

//         Ok(top_scores)
//     })
// }

// fn get_all_files_in_directory(dir: &PathBuf) -> Result<Vec<PathBuf>, std::io::Error> {
//     let mut files = Vec::new();

//     for entry in std::fs::read_dir(dir)? {
//         let entry = entry?;
//         let path = entry.path();

//         if path.is_dir() {
//             let sub_files = get_all_files_in_directory(&path)?;
//             files.extend(sub_files);
//         } else {
//             files.push(path);
//         }
//     }

//     Ok(files)
// }
