// @generated automatically by Diesel CLI.

diesel::table! {
    dependencies (id) {
        id -> Integer,
        lhs_id -> Integer,
        rhs_id -> Integer,
    }
}

diesel::table! {
    loc_info (id) {
        id -> Integer,
        #[max_length = 255]
        ident -> Varchar,
        line_num -> Integer,
        col_num -> Integer,
        #[max_length = 255]
        file_path -> Varchar,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    dependencies,
    loc_info,
);
