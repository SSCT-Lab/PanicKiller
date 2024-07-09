use super::schema::{loc_info, dependencies};
use diesel::prelude::*;

#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = loc_info)]
pub struct LocInfo {
    pub id: i32,  
    pub ident: String,
    pub line_num: i32,
    pub col_num: i32,
    pub file_path: String,
}

#[derive(Insertable)]
#[diesel(table_name = loc_info)]
pub struct NewLocInfo<'a> {
    pub ident: &'a str,
    pub line_num: i32,
    pub col_num: i32,
    pub file_path: &'a str,
}

#[derive(Queryable, Insertable, Associations, Debug)]
#[diesel(belongs_to(LocInfo, foreign_key = lhs_id))]
#[diesel(table_name = dependencies)]
pub struct Dependency {
    pub id: i32, 
    pub lhs_id: i32,
    pub rhs_id: i32,
}

#[derive(Insertable)]
#[diesel(table_name = dependencies)]
pub struct NewDependency {
    pub lhs_id: i32,
    pub rhs_id: i32,
}
