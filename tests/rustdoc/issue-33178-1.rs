// aux-build:empty.rs
// aux-build:variant-struct.rs
// ignore-cross-compile

#![crate_name="issue_33178_1"]

// @has issue_33178_1/index.html
// @!has - //a/@title empty
pub extern crate empty;

// @!has - //a/@title variant_struct
pub extern crate variant_struct as foo;
