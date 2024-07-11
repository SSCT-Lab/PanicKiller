pub mod schema;
pub mod model;

use diesel::mysql::MysqlConnection;
use diesel::prelude::*;
use dotenvy::dotenv;

pub fn establish_connection() -> MysqlConnection {
    dotenv().ok();

    let database_url = "mysql://root:root@localhost/rust_graph";
    MysqlConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}
