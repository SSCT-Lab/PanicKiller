use std::fmt::Display;
use std::path::PathBuf;
use std::io::Write;
use rustc_data_structures::fx::FxHashMap;
use syn::token::Paren;
use syn::{punctuated::Punctuated, spanned::Spanned, ExprMethodCall};

use crate::panickiller::{fault_localization::extract::FaultLoc, utils::extract_index_from_panic};
use crate::panickiller::patch_generation::patterns::PATTERN;

use super::patterns::{AddType, ChangeType, CheckType, MatchType};

pub(crate) struct Transform {
    pub output_path: Option<PathBuf>,
    pub fault_locs: Vec<FaultLoc>,
    pub patches: Vec<Patch>,
    pub file_mapping: FxHashMap<String, Vec<String>>,
    pub panic_info: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct Patch {
    pub origin: FaultLoc,
    pub file_path: String,
    pub fix_pattern: String,
    pub score: f64,
    pub panic_info: String,
    pub run_result: usize,
    pub test_result: usize,
}

impl Display for Patch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Origin: {}\nFile: {}\nPattern: {}\nScore: {}\nRun Result: {}\nTest Result: {}\n", 
            self.origin.file_path.to_str().unwrap(), 
            self.file_path, 
            self.fix_pattern.to_string(), 
            self.score,
            self.run_result,
            self.test_result,)
    }
}

impl Transform {
    pub fn new(output_path: Option<PathBuf>, fault_locs: Vec<FaultLoc>, panic_info: String) -> Self {
        Transform {
            output_path,
            fault_locs,
            patches: Vec::new(),
            file_mapping: FxHashMap::default(),
            panic_info,
        }
    }

    pub fn transform(&mut self) {  
        // Open log file
        let log_file_path = std::env::current_dir()
            .expect("Failed to get current directory")
            .parent()
            .expect("Failed to get parent directory")
            .join("src")
            .join("log.txt");
        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(log_file_path)
            .expect("Failed to open log file");  

        for (fault_index, fault_loc) in (&self.fault_locs).iter().enumerate() {
            let file_content = std::fs::read_to_string(&fault_loc.file_path)
                .expect("Failed to read!");

            writeln!(log_file, "Generating patches for file: {} in line {}", fault_loc.file_path.to_str().unwrap(), fault_loc.line_num)
                .expect("Failed to write to log file");

            let patterns: Vec<PATTERN> = vec![
                PATTERN::IndexMutate,
                PATTERN::IfPreAdd,
                PATTERN::IfPostAdd,
                PATTERN::IfCondChange,
                PATTERN::RangeChecker(CheckType::PreAdd),
                PATTERN::RangeChecker(CheckType::Wrap),
                PATTERN::MatchChange,
                PATTERN::UnsafeAdd,
                PATTERN::McAdd(AddType::AddAsBytes),
                PATTERN::McAdd(AddType::AddMax),
                PATTERN::McChange(ChangeType::ToSaturating),
                PATTERN::McChange(ChangeType::ToCheck),
                PATTERN::McChange(ChangeType::ToWrapping),
                PATTERN::McChange(ChangeType::ToFilterMap),
                PATTERN::McChange(ChangeType::ToUnwrap),
                PATTERN::McChange(ChangeType::ToUnwrapOrElse),
                PATTERN::McChange(ChangeType::ToUnwrapOrFault),
                PATTERN::McChange(ChangeType::ToExtendFromSlice),
                PATTERN::MatchAdd(MatchType::ReturnDefault),
                PATTERN::MatchAdd(MatchType::ReturnOk),
                PATTERN::MatchAdd(MatchType::ReturnErr),
                PATTERN::MatchAdd(MatchType::ReturnNone),
                PATTERN::DeleteSecondBorrow,
                PATTERN::LiteralChange,
                PATTERN::ReorderState,
            ];

            for pattern in patterns {
                // println!("Visiting ast in file: {} line {} pattern {}", fault_loc.file_path.to_str().unwrap(), fault_loc.line_num, pattern);
                let mut syntax_tree = syn::parse_file(&file_content)
                    .expect("Failed to parse file to syntax tree");

                let mut visitor = AstVisitor::new(fault_loc, pattern.clone(), self.panic_info.clone());
                syn::visit_mut::visit_file_mut(&mut visitor, &mut syntax_tree);

                if visitor.transformed {
                    let output_path = self.output_path.as_ref().expect("Output path must be specified!");

                    if !std::path::Path::new(output_path).exists() {
                        std::fs::create_dir_all(output_path).expect("Failed to create output directory!");
                    }

                    let new_file_name = format!("patch-{}_{}_{}.rs",
                        fault_index + 1,
                        fault_loc.file_path.file_stem().unwrap().to_str().unwrap(),
                        pattern);

                    let new_file_path = std::path::Path::new(output_path).join(&new_file_name);
                    println!("Writing to file: {}", new_file_path.to_str().unwrap());
                    std::fs::write(&new_file_path, prettyplease::unparse(&syntax_tree))
                        .expect("Failed to write to file!");

                    let patch = Patch {
                        origin: fault_loc.clone(),
                        file_path: new_file_path.to_str().unwrap().to_string(),
                        fix_pattern: pattern.clone().description(),
                        score: fault_loc.score,
                        panic_info: self.panic_info.clone(),
                        run_result: 101,
                        test_result: 101,
                    };

                    self.patches.push(patch);

                    self.file_mapping.entry(fault_loc.file_path.to_str().unwrap().to_string())
                        .or_insert_with(Vec::new)
                        .push(new_file_path.to_str().unwrap().to_string());
                }
            }
        }
    }
}

pub struct AstVisitor<'ast> {
    fault_loc: &'ast FaultLoc,
    fix_pattern: PATTERN,
    transformed: bool,
    panic_info: String,
}

impl<'ast> AstVisitor<'ast> {
    fn new(fault_loc: &'ast FaultLoc, fix_pattern: PATTERN, panic_info: String) -> Self {
        AstVisitor {
            fault_loc,
            fix_pattern,
            transformed: false,
            panic_info,
        }
    }

    fn transformed(&mut self) {
        self.transformed = true;
    }

    fn get_loc_num(&self) -> (i32, i32) {
        (self.fault_loc.line_num as i32, self.fault_loc.col_num as i32)
    }

    fn get_mc_idents(&self, expr: &ExprMethodCall) -> Vec<syn::Ident> {
        let mut idents = Vec::new();
        idents.push(expr.method.clone());

        let mut current_expr = &*expr.receiver;
        while let syn::Expr::MethodCall(inner_expr) = current_expr {
            idents.push(inner_expr.method.clone());
            current_expr = &*inner_expr.receiver;
        }

        idents
    }

    fn get_return(&self, ret_type: MatchType, span: proc_macro2::Span, ret_stmts: Vec<syn::Stmt>) -> syn::Stmt {
        match ret_type {
            MatchType::ReturnNone => {
                syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                    attrs: Vec::new(),
                    return_token: Default::default(),
                    expr: Some(Box::new(syn::Expr::Path(syn::ExprPath {
                        attrs: Vec::new(),
                        qself: None,
                        path: syn::Path {
                            leading_colon: None,
                            segments: Punctuated::from_iter(vec![
                                syn::PathSegment {
                                    ident: syn::Ident::new("None", span),
                                    arguments: Default::default(),
                                }
                            ]),
                        },
                    }))),
                }), None)
            },
            MatchType::ReturnOk => {
                syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                    attrs: Vec::new(),
                    return_token: Default::default(),
                    expr: Some(Box::new(syn::Expr::Call(
                        syn::ExprCall {
                            attrs: Vec::new(),
                            func: Box::new(syn::Expr::Path(syn::ExprPath {
                                attrs: Vec::new(),
                                qself: None,
                                path: syn::Path {
                                    leading_colon: None,
                                    segments: Punctuated::from_iter(vec![
                                        syn::PathSegment {
                                            ident: syn::Ident::new("Ok", span),
                                            arguments: Default::default(),
                                        }
                                    ]),
                                },
                            })),
                            paren_token: Paren::default(),
                            args: Punctuated::from_iter(vec![syn::Expr::Tuple(syn::ExprTuple {
                                attrs: Vec::new(),
                                paren_token: Paren::default(),
                                elems: Punctuated::new(),
                            })]),
                        }
                    ))),
                }), None)
            },
            MatchType::ReturnErr => {
                syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                    attrs: Vec::new(),
                    return_token: Default::default(),
                    expr: Some(Box::new(syn::Expr::Call(
                        syn::ExprCall {
                            attrs: Vec::new(),
                            func: Box::new(syn::Expr::Path(syn::ExprPath {
                                attrs: Vec::new(),
                                qself: None,
                                path: syn::Path {
                                    leading_colon: None,
                                    segments: Punctuated::from_iter(vec![
                                        syn::PathSegment {
                                            ident: syn::Ident::new("Err", span),
                                            arguments: Default::default(),
                                        }
                                    ]),
                                },
                            })),
                            paren_token: Paren::default(),
                            args: Punctuated::from_iter(vec![syn::Expr::Tuple(syn::ExprTuple {
                                attrs: Vec::new(),
                                paren_token: Paren::default(),
                                elems: Punctuated::new(),
                            })]),
                        }
                    ))),
                }), None)
            },
            MatchType::ReturnDefault => {
                let ret_stmt;
                if ret_stmts.len() == 0 {
                    ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                        attrs: Vec::new(),
                        return_token: Default::default(),
                        expr: None,
                    }), Default::default());
                } else {
                    ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                }
                ret_stmt
            },
        }
    }

}

#[allow(unused_assignments)]
impl<'ast> syn::visit_mut::VisitMut for AstVisitor<'ast> {
    fn visit_file_mut(&mut self, f: &mut syn::File) {
        syn::visit_mut::visit_file_mut(self, f);
    }

    fn visit_block_mut(&mut self, i: &mut syn::Block) {
        // println!("visit block!");
        let stmts = i.stmts.clone();

        let mut ret_stmts : Vec<syn::Stmt> = Vec::new();

        for stmt in stmts.clone() {
            if let syn::Stmt::Expr(expr, _) = stmt {
                if let syn::Expr::Return(expr_ret) = expr{
                    ret_stmts.push(syn::Stmt::Expr(syn::Expr::Return(expr_ret), Default::default()));
                } else if let syn::Expr::If(expr_if) = expr {
                    for stmts in expr_if.then_branch.stmts.clone() {
                        if let syn::Stmt::Expr(expr, _) = stmts {
                            if let syn::Expr::Return(expr_ret) = expr{
                                ret_stmts.push(syn::Stmt::Expr(syn::Expr::Return(expr_ret), Default::default()));
                            }
                        }
                    }
                } else if let syn::Expr::Match(expr_match) = expr {
                    for arm in expr_match.arms.clone() {
                        if let syn::Expr::Block(expr_block) = arm.body.clone().as_mut() {
                            for stmt in expr_block.block.stmts.clone() {
                                if let syn::Stmt::Expr(expr, _) = stmt {
                                    if let syn::Expr::Return(expr_ret) = expr{
                                        ret_stmts.push(syn::Stmt::Expr(syn::Expr::Return(expr_ret), Default::default()));
                                    }
                                }
                            }
                        } else if let syn::Expr::Return(expr_ret) = arm.body.clone().as_mut() {
                            ret_stmts.push(syn::Stmt::Expr(syn::Expr::Return(expr_ret.clone()), Default::default()));
                        }
                    }
                } else if let syn::Expr::Call(expr_call) = expr {
                    if let syn::Expr::Path(expr_path) = expr_call.func.clone().as_ref() {
                        for segment in expr_path.path.segments.clone(){
                            if segment.ident.to_string() == "Ok" {
                                let expr_ok = syn::Expr::Return(syn::ExprReturn {
                                    attrs: Vec::new(),
                                    return_token: Default::default(),
                                    expr: Some(Box::new(syn::Expr::Call(expr_call.clone()))),
                                });
    
                                ret_stmts.push(syn::Stmt::Expr(expr_ok, Default::default()));
                            }
                        }
                    }
                }
            }
        }

        for (mut index, stmt) in stmts.iter().enumerate() {
            if let syn::Stmt::Expr(expr, _) = stmt {
                match self.fix_pattern.clone() {
                    PATTERN::ReorderState => {
                        match expr {
                            syn::Expr::Macro(expr_macro) => {
                                let span = &expr_macro.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if expr_macro.mac.path.segments[0].ident.to_string() == "ready" {
                                        if index + 1 < i.stmts.len() {
                                            if index + 2 < i.stmts.len() {
                                                let tmp = i.stmts[index + 1].clone();
                                                i.stmts[index + 1] = i.stmts[index + 2].clone();
                                                i.stmts[index + 2] = tmp;
                                                self.transformed();
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::DeleteSecondBorrow => {
                        match expr {
                            syn::Expr::MethodCall(expr_call) => {
                                let span = &expr_call.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if expr_call.method.to_string() == "borrow_mut" {
                                        // remove this stmt
                                        i.stmts.remove(index);
                                        self.transformed();
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::IfPreAdd | PATTERN::IfPostAdd => {
                        match expr {
                            syn::Expr::Binary(expr_binary) => {
                                let span = &expr_binary.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                // println!("Start: {}, End: {}", start, end);
        
                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    match expr_binary.op {                                        
                                        syn::BinOp::Rem(_) | syn::BinOp::Div(_) | syn::BinOp::RemAssign(_) | syn::BinOp::DivAssign(_) => {
                                            let ident_tmp = syn::Ident::new("tmp", i.span());

                                            let expr_let = syn::Expr::Let(syn::ExprLet {
                                                attrs: Vec::new(),
                                                let_token: Default::default(),
                                                pat: Box::new(syn::Pat::Ident(syn::PatIdent {
                                                    attrs: Vec::new(),
                                                    by_ref: None,
                                                    mutability: Some(Default::default()),
                                                    ident: ident_tmp.clone(),
                                                    subpat: None,
                                                })),
                                                eq_token: Default::default(),
                                                expr: expr_binary.right.clone(),
                                            });

                                            let expr_cond = syn::Expr::Binary(syn::ExprBinary {
                                                attrs: Vec::new(),
                                                left: Box::new(syn::Expr::Path(syn::ExprPath {
                                                    attrs: Vec::new(),
                                                    qself: None,
                                                    path: syn::Path {
                                                        leading_colon: None,
                                                        segments: Punctuated::from_iter(vec![
                                                            syn::PathSegment {
                                                                ident: ident_tmp.clone(),
                                                                arguments: Default::default(),
                                                            }
                                                        ]),
                                                    },
                                                })),
                                                op: syn::BinOp::Eq(Default::default()),
                                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                                    attrs: Vec::new(),
                                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span())),
                                                })),
                                            });
            
                                            let expr_assign = syn::Expr::Assign(syn::ExprAssign {
                                                attrs: Vec::new(),
                                                left: Box::new(syn::Expr::Path(syn::ExprPath {
                                                    attrs: Vec::new(),
                                                    qself: None,
                                                    path: syn::Path {
                                                        leading_colon: None,
                                                        segments: Punctuated::from_iter(vec![
                                                            syn::PathSegment {
                                                                ident: ident_tmp.clone(),
                                                                arguments: Default::default(),
                                                            }
                                                        ]),
                                                    },
                                                })),
                                                eq_token: Default::default(),
                                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                                    attrs: Vec::new(),
                                                    lit: syn::Lit::Int(syn::LitInt::new("1", i.span())),
                                                })),
                                            });
            
                                            let then_block = syn::Block {
                                                brace_token: Default::default(),
                                                stmts: vec![syn::Stmt::Expr(expr_assign, Default::default())],
                                            };
            
                                            let expr_if = syn::Expr::If(syn::ExprIf {
                                                attrs: Vec::new(),
                                                if_token: Default::default(),
                                                cond: Box::new(expr_cond),
                                                then_branch: then_block,
                                                else_branch: None,
                                            });

                                            let expr_new_binary = syn::Expr::Binary(syn::ExprBinary {
                                                attrs: Vec::new(),
                                                left: expr_binary.left.clone(),
                                                op: expr_binary.op.clone(),
                                                right: Box::new(syn::Expr::Path(syn::ExprPath {
                                                    attrs: Vec::new(),
                                                    qself: None,
                                                    path: syn::Path {
                                                        leading_colon: None,
                                                        segments: Punctuated::from_iter(vec![
                                                            syn::PathSegment {
                                                                ident: ident_tmp.clone(),
                                                                arguments: Default::default(),
                                                            }
                                                        ]),
                                                    },
                                                })),
                                            });

                                            i.stmts[index] = syn::Stmt::Expr(expr_new_binary, Default::default());

                                            let insert_stmts = vec![
                                                syn::Stmt::Expr(expr_let, Some(syn::token::Semi::default())),
                                                syn::Stmt::Expr(expr_if, Default::default()),
                                            ];

                                            if let PATTERN::IfPostAdd = self.fix_pattern {
                                                index += 1;
                                            }

                                            i.stmts.splice(index..index, insert_stmts);

                                            self.transformed();
                                        }
                                        _ => {}
                                    }
                                }
                            },
                            syn::Expr::Match(expr_match) => {
                                let span = &expr_match.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if let syn::Expr::Call(expr_call) = expr_match.expr.clone().as_mut() {
                                        for arg in expr_call.clone().args {
                                            if let syn::Expr::MethodCall(expr_mc) = arg.clone() {
                                                if let syn::Expr::Index(expr_index) = expr_mc.clone().receiver.as_mut() {
                                                    if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                                        let expr_range_start = expr_range.start.clone();
                                                        let expr_range_end = expr_range.end.clone();
        
                                                        if expr_range_start.is_some() && expr_range_end.is_some() {
                                                            let expr_range_start = expr_range_start.unwrap();
                                                            let expr_range_end = expr_range_end.unwrap();
        
                                                            let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                                attrs: Vec::new(),
                                                                left: expr_range_start.clone(),
                                                                op: syn::BinOp::Gt(Default::default()),
                                                                right: expr_range_end.clone(),
                                                            });

                                                            let ret_stmt;
                                                            if ret_stmts.len() == 0 {
                                                                ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                                    attrs: Vec::new(),
                                                                    return_token: Default::default(),
                                                                    expr: None,
                                                                }), Default::default());
                                                            } else {
                                                                ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                            }
        
                                                            let expr_if = syn::Expr::If(syn::ExprIf {
                                                                attrs: Vec::new(),
                                                                if_token: Default::default(),
                                                                cond: Box::new(if_cond),
                                                                then_branch: syn::Block {
                                                                    brace_token: Default::default(),
                                                                    stmts: vec![ret_stmt],
                                                                },
                                                                else_branch: None,
                                                            });

                                                            if let PATTERN::IfPostAdd = self.fix_pattern {
                                                                index += 1;
                                                            }
        
                                                            i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
        
                                                            self.transformed();
                                                        
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                            if let syn::Expr::Index(expr_index) = arg.clone() {
                                                if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                                    let expr_range_start = expr_range.start.clone();
                                                    let expr_range_end = expr_range.end.clone();
    
                                                    if expr_range_start.is_some() && expr_range_end.is_some() {
                                                        let expr_range_start = expr_range_start.unwrap();
                                                        let expr_range_end = expr_range_end.unwrap();
    
                                                        let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                            attrs: Vec::new(),
                                                            left: expr_range_start.clone(),
                                                            op: syn::BinOp::Gt(Default::default()),
                                                            right: expr_range_end.clone(),
                                                        });

                                                        let ret_stmt;
                                                        if ret_stmts.len() == 0 {
                                                            ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                                attrs: Vec::new(),
                                                                return_token: Default::default(),
                                                                expr: None,
                                                            }), Default::default());
                                                        } else {
                                                            ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                        }
    
                                                        let expr_if = syn::Expr::If(syn::ExprIf {
                                                            attrs: Vec::new(),
                                                            if_token: Default::default(),
                                                            cond: Box::new(if_cond),
                                                            then_branch: syn::Block {
                                                                brace_token: Default::default(),
                                                                stmts: vec![ret_stmt],
                                                            },
                                                            else_branch: None,
                                                        });

                                                        if let PATTERN::IfPostAdd = self.fix_pattern {
                                                            index += 1;
                                                        }
    
                                                        i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
    
                                                        self.transformed();
                                                    
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::RangeChecker(check_type) => {
                        match check_type {
                            CheckType::PreAdd => {
                                match expr {
                                    syn::Expr::Index(expr_index) => {
                                        let span = &expr_index.span();
                                        let start = span.start().line;
                                        let end = span.end().line;
        
                                        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                            let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                attrs: Vec::new(),
                                                receiver: expr_index.expr.clone(),
                                                dot_token: syn::token::Dot::default(),
                                                method: syn::Ident::new("len", i.span()),
                                                turbofish: None,
                                                paren_token: Default::default(),
                                                args: Punctuated::new(),
                                            });

                                            let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                attrs: Vec::new(),
                                                left: expr_index.index.clone(),
                                                op: syn::BinOp::Ge(Default::default()),
                                                right: Box::new(expr_len.clone()),
                                            });

                                            let ret_stmt;
                                            if ret_stmts.len() == 0 {
                                                ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                    attrs: Vec::new(),
                                                    return_token: Default::default(),
                                                    expr: None,
                                                }), Default::default());
                                            } else {
                                                ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                            }
        
                                            let expr_if = syn::Expr::If(syn::ExprIf {
                                                attrs: Vec::new(),
                                                if_token: Default::default(),
                                                cond: Box::new(if_cond),
                                                then_branch: syn::Block {
                                                    brace_token: Default::default(),
                                                    stmts: vec![ret_stmt],
                                                },
                                                else_branch: None,
                                            });
        
                                            i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));

                                            self.transformed();

                                            return;
                                        }
                                    },
                                    syn::Expr::Reference(expr_ref) => {
                                        let expr_index = expr_ref.expr.as_ref();
        
                                        if let syn::Expr::Index(expr_index) = expr_index {
                                            let span = &expr_index.span();
                                            let start = span.start().line;
                                            let end = span.end().line;
        
                                            if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                                let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                    attrs: Vec::new(),
                                                    receiver: expr_index.expr.clone(),
                                                    dot_token: syn::token::Dot::default(),
                                                    method: syn::Ident::new("len", i.span()),
                                                    turbofish: None,
                                                    paren_token: Default::default(),
                                                    args: Punctuated::new(),
                                                });

                                                let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: expr_index.index.clone(),
                                                    op: syn::BinOp::Ge(Default::default()),
                                                    right: Box::new(expr_len.clone()),
                                                });

                                                let ret_stmt;
                                                if ret_stmts.len() == 0 {
                                                    ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                        attrs: Vec::new(),
                                                        return_token: Default::default(),
                                                        expr: None,
                                                    }), Default::default());
                                                } else {
                                                    ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                }
        
                                                let expr_if = syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: Box::new(if_cond),
                                                    then_branch: syn::Block {
                                                        brace_token: Default::default(),
                                                        stmts: vec![ret_stmt],
                                                    },
                                                    else_branch: None,
                                                });
        
                                                i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
        
                                                self.transformed();

                                                return;
                                            }
                                        }
                                    },
                                    syn::Expr::Assign(expr_assign) => {
                                        if let syn::Expr::Index(expr_index) = expr_assign.right.clone().as_mut() {
                                            let span = &expr_index.span();
                                            let start = span.start().line;
                                            let end = span.end().line;
            
                                            if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                                let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                    attrs: Vec::new(),
                                                    receiver: expr_index.expr.clone(),
                                                    dot_token: syn::token::Dot::default(),
                                                    method: syn::Ident::new("len", i.span()),
                                                    turbofish: None,
                                                    paren_token: Default::default(),
                                                    args: Punctuated::new(),
                                                });

                                                let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: expr_index.index.clone(),
                                                    op: syn::BinOp::Ge(Default::default()),
                                                    right: Box::new(expr_len.clone()),
                                                });

                                                let ret_stmt;
                                                if ret_stmts.len() == 0 {
                                                    ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                        attrs: Vec::new(),
                                                        return_token: Default::default(),
                                                        expr: None,
                                                    }), Default::default());
                                                } else {
                                                    ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                }
            
                                                let expr_if = syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: Box::new(if_cond),
                                                    then_branch: syn::Block {
                                                        brace_token: Default::default(),
                                                        stmts: vec![ret_stmt],
                                                    },
                                                    else_branch: None,
                                                });
            
                                                i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));

                                                self.transformed();

                                                return;
                                            }
                                        }
                                        if let syn::Expr::Reference(expr_ref) = expr_assign.right.clone().as_mut() {
                                            let expr_index = expr_ref.expr.as_ref();
                                            
                                            if let syn::Expr::Index(expr_index) = expr_index {
                                                let span = &expr_index.span();
                                                let start = span.start().line;
                                                let end = span.end().line;
            
                                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                                    let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                        attrs: Vec::new(),
                                                        receiver: expr_index.expr.clone(),
                                                        dot_token: syn::token::Dot::default(),
                                                        method: syn::Ident::new("len", i.span()),
                                                        turbofish: None,
                                                        paren_token: Default::default(),
                                                        args: Punctuated::new(),
                                                    });

                                                    let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: expr_index.index.clone(),
                                                        op: syn::BinOp::Ge(Default::default()),
                                                        right: Box::new(expr_len.clone()),
                                                    });

                                                    let ret_stmt;
                                                    if ret_stmts.len() == 0 {
                                                        ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                            attrs: Vec::new(),
                                                            return_token: Default::default(),
                                                            expr: None,
                                                        }), Default::default());
                                                    } else {
                                                        ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                    }
            
                                                    let expr_if = syn::Expr::If(syn::ExprIf {
                                                        attrs: Vec::new(),
                                                        if_token: Default::default(),
                                                        cond: Box::new(if_cond),
                                                        then_branch: syn::Block {
                                                            brace_token: Default::default(),
                                                            stmts: vec![ret_stmt],
                                                        },
                                                        else_branch: None,
                                                    });
            
                                                    i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
            
                                                    self.transformed();

                                                    return;
                                                }
                                            }
                                        }
                                    },
                                    _ => {}
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::UnsafeAdd => {
                        match expr {
                            syn::Expr::Reference(expr_ref) => {
                                let expr_index = expr_ref.expr.as_ref();

                                if let syn::Expr::Index(expr_index) = expr_index {
                                    let span = &expr_index.span();
                                    let start = span.start().line;
                                    let end = span.end().line;

                                    if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                        if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                            let expr_range = syn::Expr::Range(expr_range.clone());
     
                                            let expr_mc = syn::Expr::MethodCall(syn::ExprMethodCall{
                                                attrs: Vec::new(),
                                                receiver: expr_index.expr.clone(),
                                                dot_token: syn::token::Dot::default(),
                                                method: syn::Ident::new("get_unchecked", i.span()),
                                                turbofish: None,
                                                paren_token: Default::default(),
                                                args: Punctuated::from_iter(vec![expr_range.clone()]),
                                            });
    
                                            let expr_unsafe = syn::Expr::Unsafe(syn::ExprUnsafe {
                                                attrs: Vec::new(),
                                                unsafe_token: Default::default(),
                                                block: syn::Block {
                                                    brace_token: Default::default(),
                                                    stmts: vec![syn::Stmt::Expr(expr_mc, Default::default())],
                                                },
                                            });
    
                                            i.stmts[index] = syn::Stmt::Expr(expr_unsafe, Default::default());
                                        }
                                    }
                                }
                            },
                            syn::Expr::Index(expr_index) => {
                                let span = &expr_index.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                        let expr_range = syn::Expr::Range(expr_range.clone());

                                        let expr_mc = syn::Expr::MethodCall(syn::ExprMethodCall{
                                            attrs: Vec::new(),
                                            receiver: expr_index.expr.clone(),
                                            dot_token: syn::token::Dot::default(),
                                            method: syn::Ident::new("get_unchecked", i.span()),
                                            turbofish: None,
                                            paren_token: Default::default(),
                                            args: Punctuated::from_iter(vec![expr_range.clone()]),
                                        });

                                        let expr_unsafe = syn::Expr::Unsafe(syn::ExprUnsafe {
                                            attrs: Vec::new(),
                                            unsafe_token: Default::default(),
                                            block: syn::Block {
                                                brace_token: Default::default(),
                                                stmts: vec![syn::Stmt::Expr(expr_mc, Default::default())],
                                            },
                                        });

                                        i.stmts[index] = syn::Stmt::Expr(expr_unsafe, Some(syn::token::Semi::default()));
                                    }
                                }                                
                            },
                            syn::Expr::MethodCall(expr_mc) => {
                                let span = &expr_mc.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 { 
                                    // println!("Start: {}, End: {}", start, end);

                                    let mut new_args = expr_mc.clone().args;

                                    for (index, arg) in expr_mc.clone().args.iter().enumerate() {
                                        if let syn::Expr::Reference(expr_ref) = arg {
                                            // println!("enter ref");
                                            let expr_index = expr_ref.expr.as_ref();
    
                                            if let syn::Expr::Index(expr_index) = expr_index {
                                                // println!("enter index");
                                                if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                                    // println!("enter range");
                                                    let expr_range = syn::Expr::Range(expr_range.clone());

                                                    let expr_new_mc = syn::Expr::MethodCall(syn::ExprMethodCall{
                                                        attrs: Vec::new(),
                                                        receiver: expr_index.expr.clone(),
                                                        dot_token: syn::token::Dot::default(),
                                                        method: syn::Ident::new("get_unchecked", i.span()),
                                                        turbofish: None,
                                                        paren_token: Default::default(),
                                                        args: Punctuated::from_iter(vec![expr_range.clone()]),
                                                    });

                                                    new_args[index] = expr_new_mc;
                                                }
                                            }
                                        }
                                    }

                                    let expr_new_mc = syn::Expr::MethodCall(syn::ExprMethodCall{
                                        attrs: Vec::new(),
                                        receiver: expr_mc.receiver.clone(),
                                        dot_token: syn::token::Dot::default(),
                                        method: expr_mc.method.clone(),
                                        turbofish: expr_mc.turbofish.clone(),
                                        paren_token: expr_mc.paren_token.clone(),
                                        args: new_args,
                                    });

                                    let expr_unsafe = syn::Expr::Unsafe(syn::ExprUnsafe {
                                        attrs: Vec::new(),
                                        unsafe_token: Default::default(),
                                        block: syn::Block {
                                            brace_token: Default::default(),
                                            stmts: vec![syn::Stmt::Expr(expr_new_mc, Default::default())],
                                        },
                                    });

                                    i.stmts[index] = syn::Stmt::Expr(expr_unsafe, Some(syn::token::Semi::default()));

                                    self.transformed();

                                    return;
                                }
                            },
                            _ => {} 
                        }
                    },
                    PATTERN::IfCondChange => {
                        match expr {
                            syn::Expr::If(expr_if) => {
                                let span = &expr_if.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if let syn::Expr::Binary(expr_binary) = expr_if.clone().cond.as_ref() {
                                        if let syn::Expr::Index(expr_index) = expr_binary.clone().left.as_ref() {
                                            let expr_call = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                attrs: Vec::new(),
                                                receiver: expr_index.expr.clone(),
                                                dot_token: syn::token::Dot::default(),
                                                method: syn::Ident::new("len", i.span()),
                                                turbofish: None,
                                                paren_token: Default::default(),
                                                args: Punctuated::new(),
                                            });

                                            if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_ref() {
                                                let expr_range_left = expr_range.clone().start;
                                                let expr_range_right = expr_range.clone().end;

                                                let mut expr_cond = expr_if.cond.clone();

                                                if let Some(expr_range_left) = expr_range_left {
                                                    let expr_single_cond = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_range_left.as_ref().clone()),
                                                        op: syn::BinOp::Lt(Default::default()),
                                                        right: Box::new(expr_call.clone()),
                                                    });

                                                    expr_cond = Box::new(syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_single_cond),
                                                        op: syn::BinOp::And(Default::default()),
                                                        right: expr_cond,
                                                    }));
                                                }

                                                if let Some(expr_range_right) = expr_range_right {
                                                    let expr_single_cond = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_range_right.as_ref().clone()),
                                                        op: syn::BinOp::Lt(Default::default()),
                                                        right: Box::new(expr_call.clone()),
                                                    });

                                                    expr_cond = Box::new(syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_single_cond),
                                                        op: syn::BinOp::And(Default::default()),
                                                        right: expr_cond,
                                                    }));
                                                }

                                                let expr_new_if = syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: expr_cond,
                                                    then_branch: expr_if.then_branch.clone(),
                                                    else_branch: expr_if.else_branch.clone(),
                                                });
                                                i.stmts[index] = syn::Stmt::Expr(expr_new_if, Default::default());

                                                self.transformed();

                                                return;
                                            } else {
                                                let expr_single_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: expr_index.index.clone(),
                                                    op: syn::BinOp::Lt(Default::default()),
                                                    right: Box::new(expr_call),
                                                });
    
                                                let expr_new_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: Box::new(expr_single_cond),
                                                    op: syn::BinOp::And(Default::default()),
                                                    right: expr_if.cond.clone(),
                                                });
    
                                                i.stmts[index] = syn::Stmt::Expr(syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: Box::new(expr_new_cond),
                                                    then_branch: expr_if.then_branch.clone(),
                                                    else_branch: expr_if.else_branch.clone(),
                                                }), Default::default());
    
                                                self.transformed();
    
                                                return;
                                            }
                                        }
                                    }
                                    if let syn::Expr::MethodCall(expr_mc) = expr_if.clone().cond.as_ref() {
                                        if let syn::Expr::Index(expr_index) = expr_mc.receiver.clone().as_ref() {
                                            let expr_call = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                attrs: Vec::new(),
                                                receiver: expr_index.expr.clone(),
                                                dot_token: syn::token::Dot::default(),
                                                method: syn::Ident::new("len", i.span()),
                                                turbofish: None,
                                                paren_token: Default::default(),
                                                args: Punctuated::new(),
                                            });

                                            if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_ref() {
                                                let expr_range_left = expr_range.clone().start;
                                                let expr_range_right = expr_range.clone().end;

                                                let mut expr_cond = expr_if.cond.clone();

                                                if let Some(expr_range_left) = expr_range_left {
                                                    let expr_single_cond = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_range_left.as_ref().clone()),
                                                        op: syn::BinOp::Lt(Default::default()),
                                                        right: Box::new(expr_call.clone()),
                                                    });

                                                    expr_cond = Box::new(syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_single_cond),
                                                        op: syn::BinOp::And(Default::default()),
                                                        right: expr_cond,
                                                    }));
                                                }

                                                if let Some(expr_range_right) = expr_range_right {
                                                    let expr_single_cond = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_range_right.as_ref().clone()),
                                                        op: syn::BinOp::Lt(Default::default()),
                                                        right: Box::new(expr_call.clone()),
                                                    });

                                                    expr_cond = Box::new(syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: Box::new(expr_single_cond),
                                                        op: syn::BinOp::And(Default::default()),
                                                        right: expr_cond,
                                                    }));
                                                }

                                                let expr_new_if = syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: expr_cond,
                                                    then_branch: expr_if.then_branch.clone(),
                                                    else_branch: expr_if.else_branch.clone(),
                                                });
                                                i.stmts[index] = syn::Stmt::Expr(expr_new_if, Default::default());

                                                self.transformed();

                                                return;
                                            } else {
                                                let expr_single_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: expr_index.index.clone(),
                                                    op: syn::BinOp::Lt(Default::default()),
                                                    right: Box::new(expr_call),
                                                });
    
                                                let expr_new_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: Box::new(expr_single_cond),
                                                    op: syn::BinOp::And(Default::default()),
                                                    right: expr_if.cond.clone(),
                                                });
    
                                                i.stmts[index] = syn::Stmt::Expr(syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: Box::new(expr_new_cond),
                                                    then_branch: expr_if.then_branch.clone(),
                                                    else_branch: expr_if.else_branch.clone(),
                                                }), Default::default());
    
                                                self.transformed();
    
                                                return;
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::MatchAdd(match_type) => {
                        if let syn::Expr::MethodCall(expr_mc) = expr {
                            let span = &expr_mc.span();
                            let start = span.start().line;
                            let end = span.end().line;

                            if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                let mut has_unwrap = false;
                                if expr_mc.method == "unwrap" {
                                    has_unwrap = true;
                                }

                                let mut method = expr_mc.receiver.clone();
                                while !has_unwrap && let syn::Expr::MethodCall(mc) = method.clone().as_ref() {
                                    if mc.method == "unwrap" {
                                        has_unwrap = true;
                                        method = Box::new(mc.receiver.clone().as_ref().clone());
                                        break;
                                    }
                                    method = Box::new(mc.receiver.clone().as_ref().clone());
                                }

                                if !has_unwrap {
                                    return;
                                }

                                let some_pat = syn::Pat::TupleStruct(syn::PatTupleStruct {
                                    attrs: Vec::new(),
                                    path: syn::Path {
                                        leading_colon: None,
                                        segments: Punctuated::from_iter(vec![
                                            syn::PathSegment {
                                                ident: syn::Ident::new("Some", i.span()),
                                                arguments: syn::PathArguments::None,
                                            }
                                        ]),
                                    },
                                    qself: None,
                                    paren_token: Default::default(),
                                    elems: Punctuated::from_iter(vec![syn::Pat::Wild(syn::PatWild {
                                        attrs: Vec::new(),
                                        underscore_token: Default::default(),
                                    })]),
                                });

                                let some_arm = syn::Arm {
                                    attrs: Vec::new(),
                                    pat: some_pat,
                                    guard: None,
                                    fat_arrow_token: Default::default(),
                                    body: Box::new(syn::Expr::Block(syn::ExprBlock {
                                        attrs: Vec::new(),
                                        label: None,
                                        block: syn::Block {
                                            brace_token: Default::default(),
                                            stmts: vec![syn::Stmt::Expr(syn::Expr::MethodCall(expr_mc.clone()), Some(syn::token::Semi::default()))],
                                        },
                                    })),
                                    comma: Default::default(),
                                };

                                let ret_stmt= self.get_return(match_type, expr_mc.span(), ret_stmts.clone());

                                let none_arm = syn::Arm {
                                    attrs: Vec::new(),
                                    pat: syn::Pat::Wild(syn::PatWild {
                                        attrs: Vec::new(),
                                        underscore_token: Default::default(),
                                    }),
                                    guard: None,
                                    fat_arrow_token: Default::default(),
                                    body: Box::new(syn::Expr::Block(syn::ExprBlock {
                                        attrs: Vec::new(),
                                        label: None,
                                        block: syn::Block {
                                            brace_token: Default::default(),
                                            stmts: vec![ret_stmt],
                                        },
                                    })),
                                    comma: Default::default(),
                                };

                                let expr_match = syn::Expr::Match(syn::ExprMatch {
                                    attrs: Vec::new(),
                                    match_token: Default::default(),
                                    expr: expr_mc.receiver.clone(),
                                    brace_token: Default::default(),
                                    arms: vec![some_arm, none_arm],
                                });

                                i.stmts[index] = syn::Stmt::Expr(expr_match, Default::default());

                                self.transformed();

                                return;
                            } 
                        }
                        if let syn::Expr::Assign(expr_assign) = expr {
                            if let syn::Expr::MethodCall(expr_mc) = expr_assign.clone().right.as_ref(){
                                let span = &expr_mc.span();
                                let start = span.start().line;
                                let end = span.end().line;
                                
                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    let some_pat = syn::Pat::TupleStruct(syn::PatTupleStruct {
                                        attrs: Vec::new(),
                                        path: syn::Path {
                                            leading_colon: None,
                                            segments: Punctuated::from_iter(vec![
                                                syn::PathSegment {
                                                    ident: syn::Ident::new("Some", i.span()),
                                                    arguments: syn::PathArguments::None,
                                                }
                                            ]),
                                        },
                                        qself: None,
                                        paren_token: Default::default(),
                                        elems: Punctuated::from_iter(vec![syn::Pat::Wild(syn::PatWild {
                                            attrs: Vec::new(),
                                            underscore_token: Default::default(),
                                        })]),
                                    });

                                    let some_arm = syn::Arm {
                                        attrs: Vec::new(),
                                        pat: some_pat,
                                        guard: None,
                                        fat_arrow_token: Default::default(),
                                        body: Box::new(syn::Expr::MethodCall(expr_mc.clone())),
                                        comma: Default::default(),
                                    };

                                    let ret_stmt= self.get_return(match_type, expr_mc.span(), ret_stmts.clone());

                                    let none_arm = syn::Arm {
                                        attrs: Vec::new(),
                                        pat: syn::Pat::Wild(syn::PatWild {
                                            attrs: Vec::new(),
                                            underscore_token: Default::default(),
                                        }),
                                        guard: None,
                                        fat_arrow_token: Default::default(),
                                        body: Box::new(syn::Expr::Block(syn::ExprBlock {
                                            attrs: Vec::new(),
                                            label: None,
                                            block: syn::Block {
                                                brace_token: Default::default(),
                                                stmts: vec![ret_stmt],
                                            },
                                        })),
                                        comma: Default::default(),
                                    };

                                    let expr_match = syn::Expr::Match(syn::ExprMatch {
                                        attrs: Vec::new(),
                                        match_token: Default::default(),
                                        expr: expr_mc.receiver.clone(),
                                        brace_token: Default::default(),
                                        arms: vec![some_arm, none_arm],
                                    });

                                    let expr_assign = syn::Expr::Assign(syn::ExprAssign {
                                        attrs: Vec::new(),
                                        left: expr_assign.left.clone(),
                                        eq_token: Default::default(),
                                        right: Box::new(expr_match),
                                    });

                                    i.stmts[index] = syn::Stmt::Expr(expr_assign, Default::default());

                                    self.transformed();

                                    return;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let syn::Stmt::Local(local) = stmt {
                let expr = match local.init.as_ref() {
                    Some(init) => init.expr.as_ref(),
                    None => return,
                };
                
                match self.fix_pattern.clone() {
                    PATTERN::ReorderState => {
                        match expr {
                            syn::Expr::Macro(expr_macro) => {
                                let span = &expr_macro.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if expr_macro.mac.path.segments[0].ident.to_string() == "ready" {
                                        let mut new_tokens = proc_macro2::TokenStream::new();
                                        let mut is_question = false;

                                        for token in expr_macro.mac.tokens.clone() {
                                            if let proc_macro2::TokenTree::Punct(punct) = token {
                                                if punct.as_char() == '?' {
                                                    is_question = true;
                                                } else {
                                                    new_tokens.extend(Some(proc_macro2::TokenTree::Punct(punct)));
                                                }
                                            } else {
                                                new_tokens.extend(Some(token));
                                            }
                                        }

                                        println!("is_question: {:?}", is_question);
                                        println!("expr_macro: {:#?}", expr_macro);

                                        if is_question {
                                            let new_expr_macro = syn::ExprMacro {
                                                attrs: expr_macro.attrs.clone(),
                                                mac: syn::Macro {
                                                    path: expr_macro.mac.path.clone(),
                                                    bang_token: expr_macro.mac.bang_token.clone(),
                                                    delimiter: expr_macro.mac.delimiter.clone(),
                                                    tokens: new_tokens,
                                                },
                                            };

                                            // construct let tmp = new_expr_macro;
                                            let ident_tmp = syn::Ident::new("tmp", i.span());
                                            let new_let = syn::Stmt::Local(syn::Local {
                                                attrs: Vec::new(),
                                                let_token: Default::default(),
                                                pat: syn::Pat::Ident(syn::PatIdent {
                                                    attrs: Vec::new(),
                                                    by_ref: None,
                                                    mutability: Some(Default::default()),
                                                    ident: ident_tmp.clone(),
                                                    subpat: None,
                                                }),
                                                init: Some(syn::LocalInit {
                                                    eq_token: Default::default(),
                                                    expr: Box::new(syn::Expr::Macro(new_expr_macro)),
                                                    diverge: None,
                                                }),
                                                semi_token: Default::default(),
                                            });

                                            let new_local = syn::Stmt::Local(syn::Local {
                                                attrs: Vec::new(),
                                                let_token: Default::default(),
                                                pat: local.pat.clone(),
                                                // init: tmp?
                                                init: Some(syn::LocalInit {
                                                    eq_token: Default::default(),
                                                    expr: Box::new(syn::Expr::Try(syn::ExprTry {
                                                        attrs: Vec::new(),
                                                        expr: Box::new(syn::Expr::Path(syn::ExprPath {
                                                            attrs: Vec::new(),
                                                            qself: None,
                                                            path: syn::Path {
                                                                leading_colon: None,
                                                                segments: Punctuated::from_iter(vec![
                                                                    syn::PathSegment {
                                                                        ident: ident_tmp.clone(),
                                                                        arguments: Default::default(),
                                                                    }
                                                                ]),
                                                            },
                                                        })),
                                                        question_token: Default::default(),
                                                    })),
                                                    diverge: None,
                                                }),
                                                semi_token: Default::default()
                                            });
                                            i.stmts[index] = new_let;
                                            i.stmts.insert(index + 2, new_local);

                                            self.transformed();
                                        } else {
                                            if index + 1 < i.stmts.len() {
                                                if index + 2 < i.stmts.len() {
                                                    let tmp = i.stmts[index + 1].clone();
                                                    i.stmts[index + 1] = i.stmts[index + 2].clone();
                                                    i.stmts[index + 2] = tmp;
                                                    self.transformed();
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::DeleteSecondBorrow => {
                        match expr {
                            syn::Expr::MethodCall(expr_call) => {
                                let span = &expr_call.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if expr_call.method.to_string() == "borrow_mut" {
                                        // remove this stmt
                                        i.stmts.remove(index);
                                        self.transformed();
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::IfPreAdd | PATTERN::IfPostAdd => {
                        match expr {
                            syn::Expr::Binary(expr_binary) => {
                                let span = &expr_binary.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                // println!("Start: {}, End: {}", start, end);
        
                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    match expr_binary.op {                                        
                                        syn::BinOp::Rem(_) | syn::BinOp::Div(_) | syn::BinOp::RemAssign(_) | syn::BinOp::DivAssign(_) => {
                                            let ident_tmp = syn::Ident::new("tmp", i.span());

                                            let expr_let = syn::Expr::Let(syn::ExprLet {
                                                attrs: Vec::new(),
                                                let_token: Default::default(),
                                                pat: Box::new(syn::Pat::Ident(syn::PatIdent {
                                                    attrs: Vec::new(),
                                                    by_ref: None,
                                                    mutability: Some(Default::default()),
                                                    ident: ident_tmp.clone(),
                                                    subpat: None,
                                                })),
                                                eq_token: Default::default(),
                                                expr: expr_binary.right.clone(),
                                            });

                                            let expr_cond = syn::Expr::Binary(syn::ExprBinary {
                                                attrs: Vec::new(),
                                                left: Box::new(syn::Expr::Path(syn::ExprPath {
                                                    attrs: Vec::new(),
                                                    qself: None,
                                                    path: syn::Path {
                                                        leading_colon: None,
                                                        segments: Punctuated::from_iter(vec![
                                                            syn::PathSegment {
                                                                ident: ident_tmp.clone(),
                                                                arguments: Default::default(),
                                                            }
                                                        ]),
                                                    },
                                                })),
                                                op: syn::BinOp::Eq(Default::default()),
                                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                                    attrs: Vec::new(),
                                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span())),
                                                })),
                                            });
            
                                            let expr_assign = syn::Expr::Assign(syn::ExprAssign {
                                                attrs: Vec::new(),
                                                left: Box::new(syn::Expr::Path(syn::ExprPath {
                                                    attrs: Vec::new(),
                                                    qself: None,
                                                    path: syn::Path {
                                                        leading_colon: None,
                                                        segments: Punctuated::from_iter(vec![
                                                            syn::PathSegment {
                                                                ident: ident_tmp.clone(),
                                                                arguments: Default::default(),
                                                            }
                                                        ]),
                                                    },
                                                })),
                                                eq_token: Default::default(),
                                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                                    attrs: Vec::new(),
                                                    lit: syn::Lit::Int(syn::LitInt::new("1", i.span())),
                                                })),
                                            });
            
                                            let then_block = syn::Block {
                                                brace_token: Default::default(),
                                                stmts: vec![syn::Stmt::Expr(expr_assign, Default::default())],
                                            };
            
                                            let expr_if = syn::Expr::If(syn::ExprIf {
                                                attrs: Vec::new(),
                                                if_token: Default::default(),
                                                cond: Box::new(expr_cond),
                                                then_branch: then_block,
                                                else_branch: None,
                                            });

                                            let expr_new_binary = syn::Expr::Binary(syn::ExprBinary {
                                                attrs: Vec::new(),
                                                left: expr_binary.left.clone(),
                                                op: expr_binary.op.clone(),
                                                right: Box::new(syn::Expr::Path(syn::ExprPath {
                                                    attrs: Vec::new(),
                                                    qself: None,
                                                    path: syn::Path {
                                                        leading_colon: None,
                                                        segments: Punctuated::from_iter(vec![
                                                            syn::PathSegment {
                                                                ident: ident_tmp.clone(),
                                                                arguments: Default::default(),
                                                            }
                                                        ]),
                                                    },
                                                })),
                                            });

                                            i.stmts[index] = syn::Stmt::Local(syn::Local {
                                                attrs: Vec::new(),
                                                let_token: Default::default(),
                                                pat: local.pat.clone(),
                                                init: Some(syn::LocalInit {
                                                    eq_token: syn::token::Eq::default(),
                                                    expr: Box::new(expr_new_binary),
                                                    diverge: None,
                                                }),
                                                semi_token: Default::default(),
                                            });

                                            let insert_stmts = vec![
                                                syn::Stmt::Expr(expr_let, Some(syn::token::Semi::default())),
                                                syn::Stmt::Expr(expr_if, Default::default()),
                                            ];

                                            if let PATTERN::IfPostAdd = self.fix_pattern {
                                                index += 1;
                                            }

                                            i.stmts.splice(index..index, insert_stmts);

                                            self.transformed();
                                        }
                                        _ => {}
                                    }
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::UnsafeAdd => {
                        match expr {
                            syn::Expr::Reference(expr_ref) => {
                                let expr_index = expr_ref.expr.as_ref();

                                if let syn::Expr::Index(expr_index) = expr_index {
                                    let span = &expr_index.span();
                                    let start = span.start().line;
                                    let end = span.end().line;

                                    if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                        if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                            let expr_range = syn::Expr::Range(expr_range.clone());
     
                                            let expr_mc = syn::Expr::MethodCall(syn::ExprMethodCall{
                                                attrs: Vec::new(),
                                                receiver: expr_index.expr.clone(),
                                                dot_token: syn::token::Dot::default(),
                                                method: syn::Ident::new("get_unchecked", i.span()),
                                                turbofish: None,
                                                paren_token: Default::default(),
                                                args: Punctuated::from_iter(vec![expr_range.clone()]),
                                            });
    
                                            let expr_unsafe = syn::Expr::Unsafe(syn::ExprUnsafe {
                                                attrs: Vec::new(),
                                                unsafe_token: Default::default(),
                                                block: syn::Block {
                                                    brace_token: Default::default(),
                                                    stmts: vec![syn::Stmt::Expr(expr_mc, Default::default())],
                                                },
                                            });
    
                                            let init = syn::LocalInit {
                                                eq_token: syn::token::Eq::default(),
                                                expr: Box::new(expr_unsafe),
                                                diverge: None,
                                            };

                                            let stmt_local = syn::Local {
                                                attrs: Vec::new(),
                                                let_token: Default::default(),
                                                pat: local.pat.clone(),
                                                init: Some(init),
                                                semi_token: syn::token::Semi::default(),
                                            };

                                            i.stmts[index] = syn::Stmt::Local(stmt_local);

                                            self.transformed();
                                        }
                                    }
                                }
                            },
                            syn::Expr::Index(expr_index) => {
                                let span = &expr_index.span();
                                let start = span.start().line;
                                let end = span.end().line;

                                if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                    if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                        let expr_range = syn::Expr::Range(expr_range.clone());

                                        let expr_mc = syn::Expr::MethodCall(syn::ExprMethodCall{
                                            attrs: Vec::new(),
                                            receiver: expr_index.expr.clone(),
                                            dot_token: syn::token::Dot::default(),
                                            method: syn::Ident::new("get_unchecked", i.span()),
                                            turbofish: None,
                                            paren_token: Default::default(),
                                            args: Punctuated::from_iter(vec![expr_range.clone()]),
                                        });

                                        let expr_unsafe = syn::Expr::Unsafe(syn::ExprUnsafe {
                                            attrs: Vec::new(),
                                            unsafe_token: Default::default(),
                                            block: syn::Block {
                                                brace_token: Default::default(),
                                                stmts: vec![syn::Stmt::Expr(expr_mc, Default::default())],
                                            },
                                        });

                                        i.stmts[index] = syn::Stmt::Expr(expr_unsafe, Some(syn::token::Semi::default()));
                                    }
                                }                                
                            },
                            _ => {}
                        }
                    },
                    PATTERN::RangeChecker(check_type) => {
                        match check_type {
                            CheckType::PreAdd => {
                                match expr {
                                    syn::Expr::Index(expr_index) => {
                                        let span = &expr_index.span();
                                        let start = span.start().line;
                                        let end = span.end().line;
        
                                        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                            if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                                let expr_range_right = expr_range.clone().end;
                                                let expr_range_left = expr_range.clone().start;
    
                                                let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                    attrs: Vec::new(),
                                                    receiver: expr_index.expr.clone(),
                                                    dot_token: syn::token::Dot::default(),
                                                    method: syn::Ident::new("len", i.span()),
                                                    turbofish: None,
                                                    paren_token: Default::default(),
                                                    args: Punctuated::new(),
                                                });
    
                                                if let Some(expr_range_right) = expr_range_right {
                                                    let if_cond_left = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: expr_range_right.clone(),
                                                        op: syn::BinOp::Ge(Default::default()),
                                                        right: Box::new(expr_len.clone()),
                                                    });

                                                    let ret_stmt;
                                                    if ret_stmts.len() == 0 {
                                                        ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                            attrs: Vec::new(),
                                                            return_token: Default::default(),
                                                            expr: None,
                                                        }), Default::default());
                                                    } else {
                                                        ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                    }
    
                                                    let expr_if = syn::Expr::If(syn::ExprIf {
                                                        attrs: Vec::new(),
                                                        if_token: Default::default(),
                                                        cond: Box::new(if_cond_left),
                                                        then_branch: syn::Block {
                                                            brace_token: Default::default(),
                                                            stmts: vec![ret_stmt],
                                                        },
                                                        else_branch: None,
                                                    });
    
                                                    i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
    
                                                    self.transformed();
    
                                                    if expr_range_left.is_none() {
                                                        return;
                                                    }
                                                }

                                                if let Some(expr_range_left) = expr_range_left {
                                                    let if_cond_right = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: expr_range_left.clone(),
                                                        op: syn::BinOp::Ge(Default::default()),
                                                        right: Box::new(expr_len.clone()),
                                                    });

                                                    let ret_stmt;
                                                    if ret_stmts.len() == 0 {
                                                        ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                            attrs: Vec::new(),
                                                            return_token: Default::default(),
                                                            expr: None,
                                                        }), Default::default());
                                                    } else {
                                                        ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                    }
    
                                                    let expr_if = syn::Expr::If(syn::ExprIf {
                                                        attrs: Vec::new(),
                                                        if_token: Default::default(),
                                                        cond: Box::new(if_cond_right),
                                                        then_branch: syn::Block {
                                                            brace_token: Default::default(),
                                                            stmts: vec![ret_stmt],
                                                        },
                                                        else_branch: None,
                                                    });
    
                                                    i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
    
                                                    self.transformed();
    
                                                    return;
                                                }
                                            } else {
                                                let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                    attrs: Vec::new(),
                                                    receiver: expr_index.expr.clone(),
                                                    dot_token: syn::token::Dot::default(),
                                                    method: syn::Ident::new("len", i.span()),
                                                    turbofish: None,
                                                    paren_token: Default::default(),
                                                    args: Punctuated::new(),
                                                });
    
                                                let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                    attrs: Vec::new(),
                                                    left: expr_index.index.clone(),
                                                    op: syn::BinOp::Ge(Default::default()),
                                                    right: Box::new(expr_len),
                                                });

                                                let ret_stmt;
                                                if ret_stmts.len() == 0 {
                                                    ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                        attrs: Vec::new(),
                                                        return_token: Default::default(),
                                                        expr: None,
                                                    }), Default::default());
                                                } else {
                                                    ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                }
        
                                                let expr_if = syn::Expr::If(syn::ExprIf {
                                                    attrs: Vec::new(),
                                                    if_token: Default::default(),
                                                    cond: Box::new(if_cond),
                                                    then_branch: syn::Block {
                                                        brace_token: Default::default(),
                                                        stmts: vec![ret_stmt],
                                                    },
                                                    else_branch: None,
                                                });
        
                                                i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
                                                
                                                self.transformed();
                                            }
                                        }
                                    },
                                    syn::Expr::Reference(expr_ref) => {
                                        let expr_index = expr_ref.expr.as_ref();
        
                                        if let syn::Expr::Index(expr_index) = expr_index {
                                            let span = &expr_index.span();
                                            let start = span.start().line;
                                            let end = span.end().line;
        
                                            if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                                if let syn::Expr::Range(expr_range) = expr_index.index.clone().as_mut() {
                                                    let expr_range_right = expr_range.clone().end;
                                                    let expr_range_left = expr_range.clone().start;
        
                                                    let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                        attrs: Vec::new(),
                                                        receiver: expr_index.expr.clone(),
                                                        dot_token: syn::token::Dot::default(),
                                                        method: syn::Ident::new("len", i.span()),
                                                        turbofish: None,
                                                        paren_token: Default::default(),
                                                        args: Punctuated::new(),
                                                    });
        
                                                    if let Some(expr_range_right) = expr_range_right {
                                                        let if_cond_left = syn::Expr::Binary(syn::ExprBinary {
                                                            attrs: Vec::new(),
                                                            left: expr_range_right.clone(),
                                                            op: syn::BinOp::Ge(Default::default()),
                                                            right: Box::new(expr_len.clone()),
                                                        });

                                                        let ret_stmt;
                                                        if ret_stmts.len() == 0 {
                                                            ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                                attrs: Vec::new(),
                                                                return_token: Default::default(),
                                                                expr: None,
                                                            }), Default::default());
                                                        } else {
                                                            ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                        }
        
                                                        let expr_if = syn::Expr::If(syn::ExprIf {
                                                            attrs: Vec::new(),
                                                            if_token: Default::default(),
                                                            cond: Box::new(if_cond_left),
                                                            then_branch: syn::Block {
                                                                brace_token: Default::default(),
                                                                stmts: vec![ret_stmt],
                                                            },
                                                            else_branch: None,
                                                        });
        
                                                        i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
        
                                                        self.transformed();
        
                                                        if expr_range_left.is_none() {
                                                            return;
                                                        }
                                                    }

                                                    if let Some(expr_range_left) = expr_range_left {
                                                        let if_cond_right = syn::Expr::Binary(syn::ExprBinary {
                                                            attrs: Vec::new(),
                                                            left: expr_range_left.clone(),
                                                            op: syn::BinOp::Ge(Default::default()),
                                                            right: Box::new(expr_len.clone()),
                                                        });

                                                        let ret_stmt;
                                                        if ret_stmts.len() == 0 {
                                                            ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                                attrs: Vec::new(),
                                                                return_token: Default::default(),
                                                                expr: None,
                                                            }), Default::default());
                                                        } else {
                                                            ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                        }
        
                                                        let expr_if = syn::Expr::If(syn::ExprIf {
                                                            attrs: Vec::new(),
                                                            if_token: Default::default(),
                                                            cond: Box::new(if_cond_right),
                                                            then_branch: syn::Block {
                                                                brace_token: Default::default(),
                                                                stmts: vec![ret_stmt],
                                                            },
                                                            else_branch: None,
                                                        });
        
                                                        i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
        
                                                        self.transformed();
        
                                                        return;
                                                    }
                                                } else {
                                                    let expr_len = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                        attrs: Vec::new(),
                                                        receiver: expr_index.expr.clone(),
                                                        dot_token: syn::token::Dot::default(),
                                                        method: syn::Ident::new("len", i.span()),
                                                        turbofish: None,
                                                        paren_token: Default::default(),
                                                        args: Punctuated::new(),
                                                    });
        
                                                    let if_cond = syn::Expr::Binary(syn::ExprBinary {
                                                        attrs: Vec::new(),
                                                        left: expr_index.index.clone(),
                                                        op: syn::BinOp::Ge(Default::default()),
                                                        right: Box::new(expr_len),
                                                    });

                                                    let ret_stmt;
                                                    if ret_stmts.len() == 0 {
                                                        ret_stmt = syn::Stmt::Expr(syn::Expr::Return(syn::ExprReturn {
                                                            attrs: Vec::new(),
                                                            return_token: Default::default(),
                                                            expr: None,
                                                        }), Default::default());
                                                    } else {
                                                        ret_stmt = ret_stmts[ret_stmts.len() - 1].clone();
                                                    }
            
                                                    let expr_if = syn::Expr::If(syn::ExprIf {
                                                        attrs: Vec::new(),
                                                        if_token: Default::default(),
                                                        cond: Box::new(if_cond),
                                                        then_branch: syn::Block {
                                                            brace_token: Default::default(),
                                                            stmts: vec![ret_stmt],
                                                        },
                                                        else_branch: None,
                                                    });
            
                                                    i.stmts.insert(index, syn::Stmt::Expr(expr_if, Default::default()));
                                                    
                                                    self.transformed();
                                                }
                                            }
                                        }
                                    },
                                    _ => {}
                                }
                            },
                            _ => {}
                        }
                    },
                    PATTERN::MatchAdd(match_type) => {
                        if let syn::Expr::MethodCall(expr_mc) = expr {
                            let span = &expr_mc.span();
                            let start = span.start().line;
                            let end = span.end().line;

                            if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
                                let mut has_unwrap = false;
                                if expr_mc.method == "unwrap" {
                                    has_unwrap = true;
                                }

                                let mut method = expr_mc.receiver.clone();
                                while !has_unwrap && let syn::Expr::MethodCall(mc) = method.clone().as_ref() {
                                    if mc.method == "unwrap" {
                                        has_unwrap = true;
                                        method = Box::new(mc.receiver.clone().as_ref().clone());
                                        break;
                                    }
                                    method = Box::new(mc.receiver.clone().as_ref().clone());
                                }

                                if !has_unwrap {
                                    return;
                                }

                                let some_pat = syn::Pat::TupleStruct(syn::PatTupleStruct {
                                    attrs: Vec::new(),
                                    path: syn::Path {
                                        leading_colon: None,
                                        segments: Punctuated::from_iter(vec![
                                            syn::PathSegment {
                                                ident: syn::Ident::new("Some", i.span()),
                                                arguments: syn::PathArguments::None,
                                            }
                                        ]),
                                    },
                                    qself: None,
                                    paren_token: Default::default(),
                                    elems: Punctuated::from_iter(vec![syn::Pat::Wild(syn::PatWild {
                                        attrs: Vec::new(),
                                        underscore_token: Default::default(),
                                    })]),
                                });

                                let some_arm = syn::Arm {
                                    attrs: Vec::new(),
                                    pat: some_pat,
                                    guard: None,
                                    fat_arrow_token: Default::default(),
                                    body: Box::new(syn::Expr::MethodCall(expr_mc.clone())),
                                    comma: Default::default(),
                                };

                                let ret_stmt= self.get_return(match_type, expr_mc.span(), ret_stmts.clone());
                                
                                let none_arm = syn::Arm {
                                    attrs: Vec::new(),
                                    pat: syn::Pat::Wild(syn::PatWild {
                                        attrs: Vec::new(),
                                        underscore_token: Default::default(),
                                    }),
                                    guard: None,
                                    fat_arrow_token: Default::default(),
                                    body: Box::new(syn::Expr::Block(syn::ExprBlock {
                                        attrs: Vec::new(),
                                        label: None,
                                        block: syn::Block {
                                            brace_token: Default::default(),
                                            stmts: vec![ret_stmt],
                                        },
                                    })),
                                    comma: Default::default(),
                                };

                                let expr_match = syn::Expr::Match(syn::ExprMatch {
                                    attrs: Vec::new(),
                                    match_token: Default::default(),
                                    expr: Box::new(*method.clone()),
                                    brace_token: Default::default(),
                                    arms: vec![some_arm, none_arm],
                                });

                                let stmt_let = syn::Stmt::Expr(syn::Expr::Let(syn::ExprLet {
                                    attrs: Vec::new(),
                                    let_token: Default::default(),
                                    pat: Box::new(local.pat.clone()),
                                    eq_token: Default::default(),
                                    expr: Box::new(expr_match),
                                }), Some(syn::token::Semi::default()));

                                i.stmts[index] = stmt_let;

                                self.transformed();

                                return;
                            }
                        }
                    }
                    _ => {}
                }
                
            }
        }

        syn::visit_mut::visit_block_mut(self, i);
    }

    fn visit_expr_match_mut(&mut self, i: &mut syn::ExprMatch) {
        let span = &i.span();
        let start = span.start().line;
        let end = span.end().line;

        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
            match &self.fix_pattern {
                PATTERN::MatchChange => {
                    if let syn::Expr::Binary(expr_binary) = i.expr.as_mut() {
                        let new_expr = syn::Expr::Binary(syn::ExprBinary {
                            attrs: Vec::new(),
                            left: Box::new(syn::Expr::Binary(expr_binary.clone())),
                            op: syn::BinOp::Sub(syn::token::Minus::default()),
                            right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                attrs: Vec::new(),
                                lit: syn::Lit::Int(syn::LitInt::new("1", i.span()))
                            })),
                        });

                        i.expr = Box::new(new_expr);

                        self.transformed();
                    }
                },
                _ => {}
            }
        }
    
        syn::visit_mut::visit_expr_match_mut(self, i);
    }

    fn visit_expr_binary_mut(&mut self, i: &mut syn::ExprBinary) {
        let span = &i.span();
        let start = span.start().line;
        let end = span.end().line;

        // println!("Start: {}, End: {}", start, end);

        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 
            && self.get_loc_num().1 <= span.start().column as i32 {
            match &self.fix_pattern {
                PATTERN::McChange(ChangeType::ToSaturating) => {
                    match i.op {
                        syn::BinOp::Add(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_add = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_add", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_add),
                            };

                            self.transformed();
                        },
                        syn::BinOp::AddAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_add = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_add", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_add),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Sub(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_sub = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_sub", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_sub),
                            };

                            self.transformed();
                        },
                        syn::BinOp::SubAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_sub = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_sub", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_sub),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Mul(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_mul = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_mul", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_mul),
                            };

                            self.transformed();
                        },
                        syn::BinOp::MulAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_mul = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_mul", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg.clone()]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_mul),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Div(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_div = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_div", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_div),
                            };

                            self.transformed();
                        },
                        syn::BinOp::DivAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let saturating_div = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("saturating_div", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(saturating_div),
                            };

                            self.transformed();
                        },
                        _ => {}
                    }
                },
                PATTERN::McChange(ChangeType::ToWrapping) => {
                    match i.op {
                        syn::BinOp::Add(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_add = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_add", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg.clone()]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_add),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::AddAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_add = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_add", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_add),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Sub(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_sub = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_sub", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_sub),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::SubAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_sub = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_sub", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_sub),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Mul(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_mul = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_mul", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_mul),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::MulAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_mul = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_mul", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_mul),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Div(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_div = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_div", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_div),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::DivAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_div = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_div", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_div),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Shl(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_shl = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_shl", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_shl),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::ShlAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_shl = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_shl", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_shl),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::Shr(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_shr = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_shr", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_shr),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        syn::BinOp::ShrAssign(_) => {
                            let mut arg = i.right.clone();
                            let mut receiver = i.left.clone();

                            if let syn::Expr::Lit(_) = i.left.as_ref() {
                                arg = i.left.clone();
                                receiver = i.right.clone();
                            }

                            let wrapping_shr = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver,
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("wrapping_shr", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*arg]),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(wrapping_shr),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        _ => {},
                    }
                },
                PATTERN::McChange(ChangeType::ToCheck) => {
                    match i.op {
                        syn::BinOp::Add(_) | syn::BinOp::AddAssign(_) => {
                            let check_add = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.left.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("checked_add", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*i.right.clone()]),
                            });

                            let unwrap_or_default = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: Box::new(check_add),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("unwrap_or_default", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(unwrap_or_default),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },

                        syn::BinOp::Sub(_) | syn::BinOp::SubAssign(_) => {
                            let check_sub = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.left.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("checked_sub", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*i.right.clone()]),
                            });

                            let unwrap_or_default = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: Box::new(check_sub),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("unwrap_or_default", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(unwrap_or_default),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        
                        syn::BinOp::Mul(_) | syn::BinOp::MulAssign(_) => {
                            let check_mul = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.left.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("checked_mul", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*i.right.clone()]),
                            });

                            let unwrap_or_default = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: Box::new(check_mul),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("unwrap_or_default", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(unwrap_or_default),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        
                        syn::BinOp::Div(_) | syn::BinOp::DivAssign(_) => {
                            let check_div = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.left.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("checked_div", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*i.right.clone()]),
                            });

                            let unwrap_or_default = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: Box::new(check_div),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("unwrap_or_default", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(unwrap_or_default),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        
                        syn::BinOp::Shl(_) | syn::BinOp::ShlAssign(_) => {
                            let check_shl = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.left.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("checked_shl", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*i.right.clone()]),
                            });

                            let unwrap_or_default = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: Box::new(check_shl),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("unwrap_or_default", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(unwrap_or_default),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        
                        syn::BinOp::Shr(_) | syn::BinOp::ShrAssign(_) => {
                            let check_shr = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.left.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("checked_shr", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::from_iter(vec![*i.right.clone()]),
                            });

                            let unwrap_or_default = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: Box::new(check_shr),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("unwrap_or_default", i.op.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            *i = syn::ExprBinary {
                                attrs: Vec::new(),
                                left: Box::new(unwrap_or_default),
                                op: syn::BinOp::Add(Default::default()),
                                right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                    attrs: Vec::new(),
                                    lit: syn::Lit::Int(syn::LitInt::new("0", i.span()))
                                })),
                            };

                            self.transformed();
                        },
                        _ => {}
                    }
                },
                PATTERN::McAdd(AddType::AddMax) => {
                    if let syn::BinOp::Div(_) = i.op {
                        let max = syn::Expr::MethodCall(syn::ExprMethodCall {
                            attrs: Vec::new(),
                            receiver: i.right.clone(),
                            dot_token: syn::token::Dot::default(),
                            method: syn::Ident::new("max", i.span()),
                            turbofish: None,
                            paren_token: Default::default(),
                            args: Punctuated::from_iter(vec![syn::Expr::Lit(syn::ExprLit {
                                attrs: Vec::new(),
                                lit: syn::Lit::Int(syn::LitInt::new("1", i.span()))
                            })]),
                        });
    
                        i.right = Box::new(max);

                        self.transformed();
                    }

                    if let syn::BinOp::DivAssign(_) = i.op {
                        let max = syn::Expr::MethodCall(syn::ExprMethodCall {
                            attrs: Vec::new(),
                            receiver: i.right.clone(),
                            dot_token: syn::token::Dot::default(),
                            method: syn::Ident::new("max", i.span()),
                            turbofish: None,
                            paren_token: Default::default(),
                            args: Punctuated::from_iter(vec![syn::Expr::Lit(syn::ExprLit {
                                attrs: Vec::new(),
                                lit: syn::Lit::Int(syn::LitInt::new("1", i.span()))
                            })]),
                        });
    
                        i.right = Box::new(max);

                        self.transformed();
                    }
                }
                _ => {}
            }
        }

        syn::visit_mut::visit_expr_binary_mut(self, i);
    }

    fn visit_expr_index_mut(&mut self, i: &mut syn::ExprIndex) {
        // println!("visit_expr_index_mut!");
        let span = &i.span();
        let start = span.start().line;
        let end = span.end().line;

        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
            match &self.fix_pattern {
                PATTERN::IndexMutate => {
                    let span = i.index.span();

                    let index_mutate = extract_index_from_panic(self.panic_info.clone()).unwrap_or(1);

                    if let syn::Expr::Binary(expr_binary) = i.index.as_mut() {
                        let new_expr = syn::Expr::Binary(syn::ExprBinary {
                            attrs: Vec::new(),
                            left: Box::new(syn::Expr::Binary(expr_binary.clone())),
                            op: syn::BinOp::Sub(syn::token::Minus::default()),
                            right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                attrs: Vec::new(),
                                lit: syn::Lit::Int(syn::LitInt::new(index_mutate.to_string().as_str(), span)),
                            })),
                        });

                        i.index = Box::new(new_expr); 

                        self.transformed();
                    }

                    if let syn::Expr::Range(expr_range) = i.index.as_mut() {
                        match &expr_range.end {
                            Some(end_expr) => {
                                let new_end_expr = syn::Expr::Binary(syn::ExprBinary {
                                    attrs: Vec::new(),
                                    left: end_expr.clone(),
                                    op: syn::BinOp::Sub(syn::token::Minus::default()),
                                    right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                        attrs: Vec::new(),
                                        lit: syn::Lit::Int(syn::LitInt::new(index_mutate.to_string().as_str(), span)),
                                    })),
                                });

                                expr_range.end = Some(Box::new(new_end_expr));

                                self.transformed();
                            }
                            None => {},
                        };

                        match &expr_range.start {
                            Some(start_expr) => {
                                let new_start_expr = syn::Expr::Binary(syn::ExprBinary {
                                    attrs: Vec::new(),
                                    left: start_expr.clone(),
                                    op: syn::BinOp::Sub(syn::token::Minus::default()),
                                    right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                        attrs: Vec::new(),
                                        lit: syn::Lit::Int(syn::LitInt::new(index_mutate.to_string().as_str(), span)),
                                    })),
                                });

                                expr_range.start = Some(Box::new(new_start_expr));

                                self.transformed();
                            }
                            None => {
                                return;
                            }
                        }
                    }

                    if let syn::Expr::Path(expr_path) = i.index.as_mut() {
                        let new_expr = syn::Expr::Binary(syn::ExprBinary {
                            attrs: Vec::new(),
                            left: Box::new(syn::Expr::Path(expr_path.clone())),
                            op: syn::BinOp::Sub(syn::token::Minus::default()),
                            right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                attrs: Vec::new(),
                                lit: syn::Lit::Int(syn::LitInt::new(index_mutate.to_string().as_str(), span)),
                            })),
                        });

                        i.index = Box::new(new_expr); 

                        self.transformed();
                    }

                    if let syn::Expr::Lit(expr_lit) = i.index.as_mut() {
                        let new_expr = syn::Expr::Binary(syn::ExprBinary {
                            attrs: Vec::new(),
                            left: Box::new(syn::Expr::Lit(expr_lit.clone())),
                            op: syn::BinOp::Sub(syn::token::Minus::default()),
                            right: Box::new(syn::Expr::Lit(syn::ExprLit {
                                attrs: Vec::new(),
                                lit: syn::Lit::Int(syn::LitInt::new(index_mutate.to_string().as_str(), span)),
                            })),
                        });

                        i.index = Box::new(new_expr); 

                        self.transformed();
                    }
                },
                _ => {}
            }
        }
        
        syn::visit_mut::visit_expr_index_mut(self, i);
    }

    fn visit_expr_method_call_mut(&mut self, i: &mut syn::ExprMethodCall) {
        let span = &i.span();
        let start = span.start().line;
        let end = span.end().line;

        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
            match &self.fix_pattern {
                PATTERN::McAdd(add_type) => {
                    match add_type {
                        AddType::AddAsBytes => {
                            let new_receiver = syn::Expr::MethodCall(syn::ExprMethodCall {
                                attrs: Vec::new(),
                                receiver: i.receiver.clone(),
                                dot_token: syn::token::Dot::default(),
                                method: syn::Ident::new("as_bytes", i.method.span()),
                                turbofish: None,
                                paren_token: Default::default(),
                                args: Punctuated::new(),
                            });

                            i.receiver = Box::new(new_receiver);

                            self.transformed();

                            return;
                        },
                        _ => {}
                    }
                }, 
                PATTERN::McChange(change_type) => {
                    match change_type {
                        ChangeType::ToFilterMap => {
                            if i.method.to_string() == "map" {
                                if let syn::Expr::Closure(ref mut expr_closure) = *i.args.first_mut().unwrap() {
                                    if let syn::Expr::MethodCall(ref mut expr_mc) = expr_closure.body.as_mut() {
                                        let mut idents: Vec<syn::Ident> = self.get_mc_idents(&expr_mc);
                                        idents.reverse();

                                        // println!("{:?}", idents);

                                        let unwrap_index = idents.iter().position(|ident| ident.to_string() == "unwrap");
                                        idents = match unwrap_index {
                                            Some(index) => {
                                                idents.into_iter().skip(index + 1).collect()
                                            },
                                            None => {
                                                return;
                                            }
                                        };

                                        let closure_arg = syn::Pat::Ident(syn::PatIdent {
                                            attrs: Vec::new(),
                                            by_ref: None,
                                            mutability: None,
                                            ident: syn::Ident::new("a", i.method.span()),
                                            subpat: None,
                                        });

                                        let mut closure_body = syn::Expr::MethodCall(syn::ExprMethodCall {
                                            attrs: Vec::new(),
                                            receiver: Box::new(syn::Expr::Path(syn::ExprPath {
                                                attrs: Vec::new(),
                                                qself: None,
                                                path: syn::Path {
                                                    leading_colon: None,
                                                    segments: syn::punctuated::Punctuated::from_iter(vec![
                                                        syn::PathSegment {
                                                            ident: syn::Ident::new("a", i.method.span()),
                                                            arguments: syn::PathArguments::None,
                                                        }
                                                    ]),
                                                },
                                            })),
                                            dot_token: syn::token::Dot::default(),
                                            method: idents[0].clone(),
                                            turbofish: None,
                                            paren_token: Default::default(),
                                            args: Punctuated::new(),
                                        });

                                        for ident in &idents[1..] {
                                            let new_closure_body = syn::Expr::MethodCall(syn::ExprMethodCall {
                                                attrs: Vec::new(),
                                                receiver: Box::new(closure_body),
                                                dot_token: syn::token::Dot::default(),
                                                method: ident.clone(),
                                                turbofish: None,
                                                paren_token: Default::default(),
                                                args: Punctuated::new(),
                                            });

                                            closure_body = new_closure_body;
                                        }

                                        let closure = syn::Expr::Closure(syn::ExprClosure {
                                            attrs: Vec::new(),
                                            lifetimes: None,
                                            constness: None,
                                            movability: None,
                                            asyncness: None,
                                            capture: None,
                                            or1_token: Default::default(),
                                            inputs: syn::punctuated::Punctuated::from_iter(vec![closure_arg]),
                                            or2_token: Default::default(),
                                            output: syn::ReturnType::Default,
                                            body: Box::new(closure_body),
                                        });

                                        let mut tmp_expr_mc = expr_mc.clone();
                                        while let syn::Expr::MethodCall(ref mut inner_expr) = tmp_expr_mc.receiver.as_mut() {
                                            if inner_expr.method.to_string() == "unwrap" {
                                                inner_expr.method = syn::Ident::new("map", inner_expr.method.span());
                                                inner_expr.args.clear();
                                                inner_expr.args.push(closure);

                                                expr_closure.body = Box::new(syn::Expr::MethodCall(inner_expr.clone()));

                                                break;
                                            }

                                            tmp_expr_mc = inner_expr.clone();
                                        }
                                    }
                                }

                                i.method = syn::Ident::new("filter_map", i.method.span());

                                self.transformed();
                            }
                        },
                        ChangeType::ToExtendFromSlice => {
                            if i.method.to_string() == "copy_from_slice" {
                                i.method = syn::Ident::new("extend_from_slice", i.method.span());

                                self.transformed();
                            }
                        },
                        ChangeType::ToSaturating => {
                            if i.method.to_string() == "abs" {
                                i.method = syn::Ident::new("saturating_abs", i.method.span());

                                self.transformed();
                            }
                        },
                        ChangeType::ToWrapping => {
                            if i.method.to_string() == "abs" {
                                i.method = syn::Ident::new("wrapping_abs", i.method.span());

                                self.transformed();
                            }
                        },
                        ChangeType::ToUnwrapOrElse => {
                            if i.method.to_string() == "expect" {
                                i.method = syn::Ident::new("unwrap_or_else", i.method.span());

                                let closure_body = syn::Expr::MethodCall(syn::ExprMethodCall {
                                    attrs: Vec::new(),
                                    receiver: Box::new(syn::Expr::Lit(syn::ExprLit {
                                        attrs: Vec::new(),
                                        lit: syn::Lit::Int(syn::LitInt::new("1", i.method.span())),
                                    })),
                                    dot_token: syn::token::Dot::default(),
                                    method: syn::Ident::new("into", i.method.span()),
                                    turbofish: None,
                                    paren_token: Default::default(),
                                    args: Punctuated::new(),
                                });

                                let closure = syn::Expr::Closure(syn::ExprClosure {
                                    attrs: Vec::new(),
                                    lifetimes: None,
                                    constness: None,
                                    movability: None,
                                    asyncness: None,
                                    capture: None,
                                    or1_token: Default::default(),
                                    inputs: syn::punctuated::Punctuated::new(),
                                    or2_token: Default::default(),
                                    output: syn::ReturnType::Default,
                                    body: Box::new(closure_body),
                                });

                                i.args.clear();
                                i.args.push(closure);

                                // println!("{:?}", i.args);

                                self.transformed();
                            }
                        },
                        ChangeType::ToUnwrapOrFault => {
                            if i.method.to_string() == "expect" {
                                i.method = syn::Ident::new("unwrap_or_default", i.method.span());
                                i.args.clear();

                                self.transformed();
                            }

                            if i.method.to_string() == "unwrap" {
                                i.method = syn::Ident::new("unwrap_or_default", i.method.span());
                                i.args.clear();

                                self.transformed();
                            }
                        },
                        _ => {}
                    }
                },
                _ => {}
            }
        }

        syn::visit_mut::visit_expr_method_call_mut(self, i);
    }

    fn visit_lit_int_mut(&mut self, i: &mut syn::LitInt) {
        let span = &i.span();
        let start = span.start().line;
        let end = span.end().line;

        if self.get_loc_num().0 <= end as i32 && self.get_loc_num().0 >= start as i32 {
            match &self.fix_pattern {
                PATTERN::LiteralChange => {
                    // change 0 to 1
                    if i.base10_digits() == "0" {
                        let lit_1 = syn::LitInt::new("1", i.span());
                        *i = lit_1;
                        self.transformed();
                    }
                },
                _ => {}
            }
        }

        syn::visit_mut::visit_lit_int_mut(self, i);
    }
}
