mod utils;
mod database;
mod fault_localization;
mod patch_generation;
mod patch_validation;

use std::path::PathBuf;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
use rustc_data_structures::fx::FxHashMap;
use rustc_middle::ty::TyCtxt;

use crate::panickiller::fault_localization::graph::{DependencyGraph, GraphVisitor};
use crate::panickiller::patch_generation::patch::Transform;
// use crate::panickiller::fault_localization::extract::extract_backtrace;
// use crate::panickiller::patch_generation::rank::PatchRanker;
// use crate::panickiller::patch_validation::validation::Validator;

// location-baseline3(backtrace random)
// use crate::tooling::utils::get_random_location_from_fault_locs;

// location-baseline4(nlp)
use crate::panickiller::utils::get_fault_loc_from_simi;

pub fn analyze_dependencies(tcx: TyCtxt<'_>) {
    let start_time = Instant::now();

    // Open log file
    let log_file_path = std::env::current_dir()
        .expect("Failed to get current directory")
        .parent()
        .expect("Failed to get parent directory")
        .join("src")
        .join("log.txt");
    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(log_file_path)
        .expect("Failed to open log file");

    let panic_path = std::env::current_dir()
        .expect("Failed to get current directory")
        .parent()
        .expect("Failed to get parent directory")
        .join("src")
        .join("panic_info.txt");
    let panic_info = std::fs::read_to_string(panic_path).expect("Failed to read panic info");

    println!("Analysis begins.");
    // Log start of analysis
    writeln!(log_file, "Analysis begins.").expect("Failed to write to log file");

    println!("Dependency graph generation begins.");
    // Analyze dependencies
    writeln!(log_file, "Dependency graph generation begins.").expect("Failed to write to log file");
    let hir = tcx.hir();
    let mut dependency_graph: DependencyGraph<'_> = DependencyGraph {
        tcx,
        hir,
        lhs_to_loc_info: FxHashMap::default(),
    };
    let mut visitor = GraphVisitor::new(&mut dependency_graph);
    tcx.hir().walk_toplevel_module(&mut visitor);
    for (lhs, rhs_vec) in &visitor.graph.lhs_to_loc_info {
        writeln!(log_file, "LHS: {:?}", lhs).expect("Failed to write to log file");
        for rhs in rhs_vec {
            writeln!(log_file, "\tRHS: {:?}", rhs).expect("Failed to write to log file");
        }
    }

    // Insert dependency graph
    utils::insert_dependency_graph(&mut dependency_graph);
    println!("Dependency graph generation ends.");

    println!("Fault localization begins.");
    // Extract backtrace
    writeln!(log_file, "Fault localization begins.").expect("Failed to write to log file");
    // let fault_locs = extract_backtrace(PathBuf::from("../src/backtrace"));
    // let fault_locs = utils::get_perfect_location();
    println!("Get locations!");
    let fault_locs = get_fault_loc_from_simi(panic_info.clone()).unwrap();
    for fault_loc in fault_locs.clone() {
        println!("{:?}", fault_loc);
        writeln!(log_file, "{:?}", fault_loc).expect("Failed to write to log file");
    }
    println!("Fault localization ends.");

    // Patch generation
    println!("Patch Generation begins.");
    writeln!(log_file, "Patch Generation begins.").expect("Failed to write to log file");
    let output_path = Some(PathBuf::from("../src/patches"));

    // location-baseline3(backtrace random)
    // let mut transform = Transform::new(output_path, get_random_location_from_fault_locs(fault_locs.clone()), panic_info);

    // location-baseline4(nlp)
    let mut _transform = Transform::new(output_path, get_fault_loc_from_simi(panic_info.clone()).unwrap(), panic_info.clone());

    // let mut transform: Transform = Transform::new(output_path, fault_locs.clone(), panic_info);
    // transform.transform();
    // println!("Patch Generation ends: {:#?}", transform.file_mapping);
    // writeln!(log_file, "Patch Generation ends: {:#?}.", transform.file_mapping).expect("Failed to write to log file");

    // Patch validation
    println!("Patch Validation begins.");
    writeln!(log_file, "Patch Validation begins.").expect("Failed to write to log file");
    // let mut _validator = Validator::new(transform.patches.iter_mut().collect());
    // validator.validate();
    println!("Patch Validation ends.");
    writeln!(log_file, "Patch Validation ends.").expect("Failed to write to log file");

    // Log end of analysis
    println!("Analysis ends.");
    writeln!(log_file, "Analysis ends.").expect("Failed to write to log file");

    // Rank patches
    // let mut patch_ranker = PatchRanker::new(transform.patches);
    // patch_ranker.rank_patches().expect("Failed to rank patches");

    // Print some console output as well
    println!("Analysis completed. Check log.txt for details. Results are also logged in result.txt.");

    // Open result file
    let result_file_path = std::env::current_dir()
        .expect("Failed to get current directory")
        .parent()
        .expect("Failed to get parent directory")
        .join("src")
        .join("result.txt");
    let mut result_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(result_file_path)
        .expect("Failed to open result file");

    // Print ranked fault locations and log ranked fault locations
    println!("Ranked fault locations:");
    writeln!(result_file, "Ranked fault locations:").expect("Failed to write to log file");
    for (rank, fault_loc) in fault_locs.iter().enumerate() {
        println!("Rank {}: {:#?}", rank + 1, fault_loc);
        writeln!(result_file, "Rank {}: {:#?}", rank + 1, fault_loc).expect("Failed to write to log file");
    }

    // Print ranked patches and log ranked patches
    // println!("Ranked patches:");
    // writeln!(result_file, "Ranked patches:").expect("Failed to write to log file");
    // for (rank, patch) in patch_ranker.patches.iter().enumerate() {
    //     println!("Rank {}: {}", rank + 1, patch);
    //     writeln!(result_file, "Rank {}: {}", rank + 1, patch).expect("Failed to write to log file");
    // }

    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);

    println!("Total analysis time: {:?}", elapsed_time);
    writeln!(result_file, "Total analysis time: {:?}", elapsed_time).expect("Failed to write to log file");
}
