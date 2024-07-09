use std::path::PathBuf;

use rustc_data_structures::fx::FxHashMap;

use rustc_middle::ty::TyCtxt;
use rustc_middle::hir::map::Map;
use rustc_session::Session;
use rustc_span::def_id::LocalDefId;
use rustc_span::source_map::SourceMap;
use rustc_hir::intravisit::{FnKind, Visitor};
use rustc_hir::{BodyId, Expr, ExprKind, FnDecl, HirId, QPath};
use rustc_hir::Node;
use rustc_span::Span;

use crate::panickiller::utils;

#[derive(Debug, Eq, Hash, PartialEq, Clone)] 
pub(crate) struct LocInfo {
    pub ident: String,
    pub line_num: usize,
    pub col_num: usize,
    pub file_path: PathBuf,
}

pub(crate) struct DependencyGraph<'tcx> {
    pub tcx: TyCtxt<'tcx>,
    pub hir: Map<'tcx>,
    pub lhs_to_loc_info: FxHashMap<LocInfo, Vec<LocInfo>>,
}

impl<'tcx> DependencyGraph<'tcx> {
    fn sess(&self) -> &'tcx Session {
        self.tcx.sess
    }

    fn source_map(&self) -> &SourceMap {
        self.sess().source_map()
    }
}

pub struct GraphVisitor<'a, 'tcx> {
    pub graph: &'a mut DependencyGraph<'tcx>,
    current_body_id: Option<rustc_hir::BodyId>,
}

impl<'a, 'tcx> GraphVisitor<'a, 'tcx> {
    pub fn new(graph: &'a mut DependencyGraph<'tcx>) -> Self {
        GraphVisitor {
            graph,
            current_body_id: None,
        }
    }

    fn update_current_body_id(&mut self, body_id: Option<rustc_hir::BodyId>) {
        self.current_body_id = body_id;
    }
}

impl GraphVisitor<'_, '_> {
    // extract for lhs in assign expr
    fn extract_loc_info(&self, expr: &Expr<'_>) -> Option<LocInfo> {
        if let ExprKind::Path(qpath) = &expr.kind {
            if let QPath::Resolved(_, path) = qpath {
                if let Some(segment) = path.segments.last() {
                    let ident = segment.ident.to_string();
                    let src_map = self.graph.source_map();
                    let span = segment.ident.span;
        
                    let file_path = src_map.span_to_filename(span);
                    let start_pos = src_map.lookup_char_pos(span.lo());
        
                    return Some(LocInfo {
                        ident,
                        line_num: start_pos.line,
                        col_num: start_pos.col_display,
                        file_path: utils::filename_to_pathbuf(&file_path),
                    });
                }
            }
        }

        None
    }

    // extract info for rhs(s)
    fn extract_loc_infos(&self, expr: &Expr<'_>) -> Option<Vec<LocInfo>> {
        // println!("rhs: {:?}", expr);   
        match expr.kind {
            ExprKind::Binary(_, lhs, rhs) => {
                let mut loc_infos = Vec::new();
    
                if let Some(lhs_loc_infos) = self.extract_loc_infos(lhs) {
                    loc_infos.extend(lhs_loc_infos);
                }
    
                if let Some(rhs_loc_infos) = self.extract_loc_infos(rhs) {
                    // println!("rhs: {:?}", rhs);
                    loc_infos.extend(rhs_loc_infos);
                }
    
                Some(loc_infos)
            },
            ExprKind::Call(expr, _) => {
                if let Some((hir_id, ident)) = self.get_hir_id_and_ident(expr) {
                    if let Some(loc_info) = self.extract_loc_info_from_hir_id(hir_id, ident) {
                        Some(vec![loc_info])
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            ExprKind::MethodCall(method_name, _, _, _) => {
                match self.current_body_id {
                    Some(body) => {
                        let typeck_results = self.graph.tcx.typeck_body(body);
                        let def_id = typeck_results.type_dependent_def(expr.hir_id);
                        match def_id {
                            Some((_, def_id)) => {
                                if let Ok(span) = self.graph.tcx.span_of_impl(def_id) {
                                    let src_map = self.graph.source_map();
                                    let file_path = src_map.span_to_filename(span);
                                    let start_pos = src_map.lookup_char_pos(span.lo());

                                    let loc_info = LocInfo {
                                        ident: method_name.ident.to_string(),
                                        line_num: start_pos.line,
                                        col_num: start_pos.col_display,
                                        file_path: utils::filename_to_pathbuf(&file_path),
                                    };
                                    
                                    return Some(vec![loc_info]);
                                }               
                            },
                            None => return None
                        }
                    },
                    None => return None
                }
                None
            },
            ExprKind::Field(base_expr, _filed_ident) => {
                if let Some((hir_id, ident)) = self.get_hir_id_and_ident(base_expr) {
                    // println!("ident: {}", ident);
                    if let Some(loc_info) = self.extract_loc_info_from_hir_id(hir_id, ident) {
                        // println!("loc_info: {:?}", loc_info);
                        return Some(vec![loc_info])
                    } else {
                        return None
                    }
                } else {
                    return None
                }
            },
            ExprKind::Path(_) => {
                if let Some((hir_id, ident)) = self.get_hir_id_and_ident(expr) {
                    if let Some(loc_info) = self.extract_loc_info_from_hir_id(hir_id, ident) {
                        Some(vec![loc_info])
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            ExprKind::Index(array_expr, index_expr, _) => {
                let mut loc_infos = Vec::new();

                if let Some(array_loc_info) = self.extract_loc_info(array_expr) {
                    loc_infos.push(array_loc_info);
                }

                if let Some(index_loc_info) = self.extract_loc_info(index_expr) {
                    // println!("index_expr: {:?}", index_expr);
                    loc_infos.push(index_loc_info);
                }

                Some(loc_infos)
            },
            _ => None,
        }
    }
    
    fn get_hir_id_and_ident(&self, expr: &Expr<'_>) -> Option<(HirId, String)> {
        // println!("ExprKind: {:?}", expr.kind);
        if let ExprKind::Path(qpath) = &expr.kind {
            if let QPath::Resolved(_, path) = qpath {
                if let rustc_hir::def::Res::Local(id) = path.res {
                    if let Some(segment) = path.segments.last() {
                        let ident = segment.ident.to_string();
                        return Some((id, ident));
                    } else  {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        }
        None
    }

    fn extract_loc_info_from_hir_id(&self, hir_id: HirId, ident: String) -> Option<LocInfo> {
        use crate::rustc_hir::intravisit::Map;
        
        let hir = self.graph.hir;
        
        let node = hir.hir_node(hir_id);

        let src_map = self.graph.source_map();
        let span = match node {                
            Node::Expr(expr) => expr.span,
            Node::Item(item) => item.span,
            Node::Pat(pat) => pat.span,
            _ => {
                println!("node kind: {:?}", node);
                return None;
            }, 
        };
        let file_path = src_map.span_to_filename(span);
        let start_pos = src_map.lookup_char_pos(span.lo());

        // println!("ident: {ident}, node kind: {:?}", node);
        Some(
            LocInfo {
                ident,
                line_num: start_pos.line,
                col_num: start_pos.col_display,
                file_path: utils::filename_to_pathbuf(&file_path),
            }
        )
    }

    // fn extract_ident_from_pat(&self, pat: rustc_hir::Pat<'_>) -> Option<String> {
    //     use rustc_hir::PatKind::*;
    //     match pat.kind {
    //         Binding(_, _, ident, None) => Some(ident.to_string()),
    //         _ => None,
    //     }
    // }
}

impl<'a, 'tcx> Visitor<'tcx> for GraphVisitor<'a, 'tcx> {
    type Map = rustc_middle::hir::map::Map<'tcx>;
    type NestedFilter = rustc_middle::hir::nested_filter::All;

    fn nested_visit_map(&mut self) -> Self::Map {
        self.graph.tcx.hir()
    }

    fn visit_fn(&mut self, fk: FnKind<'tcx>, fd: &'tcx FnDecl<'tcx>, b: BodyId, _: Span, id: LocalDefId) {
        // println!("visit fn: {:?}", id);
        let old_id = self.current_body_id;
        self.update_current_body_id(Some(b));
        rustc_hir::intravisit::walk_fn(self, fk, fd, b, id);
        self.update_current_body_id(old_id);

    }

    // fn visit_local(&mut self, local: &'tcx Local<'tcx>) {
    //     if let Some(ident) = self.extract_ident_from_pat(*local.pat) {
    //         if let Some(init_expr) = local.init {
    //             if let Some(rhs_loc_infos) = self.extract_loc_infos(init_expr) {
    //                 // FIXME: local.pat can be 'mut x' -> start_pos starts from mut, not x
    //                 let span = local.pat.span;
    //                 let src_map = self.graph.source_map();
    //                 let start_pos = src_map.lookup_char_pos(span.lo());
    //                 let file_path = src_map.span_to_filename(span);

    //                 // println!("Visiting local stmt: {}", ident);

    //                 let lhs_loc_info = LocInfo {
    //                     ident,
    //                     line_num: start_pos.line,
    //                     col_num: start_pos.col_display,
    //                     file_path: utils::filename_to_pathbuf(&file_path),
    //                 };

    //                 // println!("lhs_loc_info: {:?}", lhs_loc_info);

    //                 self.graph.lhs_to_loc_info.entry(lhs_loc_info)
    //                     .or_insert(Vec::new())
    //                     .extend(rhs_loc_infos)
    //             }
    //         }
    //     }

    //     rustc_hir::intravisit::walk_local(self, local);
    // }
    

    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) {
        if let ExprKind::Assign(lhs, rhs, _) = &ex.kind {
            // println!("Visiting assign expr.");
            // Extract location information for the lhs of the assignment
            if let Some(lhs_loc_info) = self.extract_loc_info(lhs) {
                // Initialize a vector to hold LocInfo objects for all expressions contributing to the rhs value
                let mut rhs_loc_infos = Vec::new();

                // Recursively visit rhs to extract location information for all contributing expressions
                if let Some(rhs_info) = self.extract_loc_infos(rhs) {
                    rhs_loc_infos.extend(rhs_info);
                }

                // Update the lhs_to_loc_info map in the DependencyGraph
                // If there's already an entry for this lhs, append to it; otherwise, create a new entry
                if !rhs_loc_infos.is_empty() {
                    self.graph.lhs_to_loc_info.entry(lhs_loc_info)
                    .and_modify(|e| e.extend(rhs_loc_infos.clone()))
                    .or_insert(rhs_loc_infos);
                }
            }
        } else if let ExprKind::AssignOp(_, lhs, rhs) = &ex.kind {
            if let Some(lhs_loc_info) = self.extract_loc_info(lhs) {
                // Initialize a vector to hold LocInfo objects for all expressions contributing to the rhs value
                let mut rhs_loc_infos = Vec::new();

                // Recursively visit rhs to extract location information for all contributing expressions
                if let Some(rhs_info) = self.extract_loc_infos(rhs) {
                    rhs_loc_infos.extend(rhs_info);
                }

                // Update the lhs_to_loc_info map in the DependencyGraph
                // If there's already an entry for this lhs, append to it; otherwise, create a new entry
                if !rhs_loc_infos.is_empty() {
                    self.graph.lhs_to_loc_info.entry(lhs_loc_info)
                    .and_modify(|e| e.extend(rhs_loc_infos.clone()))
                    .or_insert(rhs_loc_infos);
                }
            }
        }

        rustc_hir::intravisit::walk_expr(self, ex);
    }
}
