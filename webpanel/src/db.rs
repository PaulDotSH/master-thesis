use bb8::Pool;
use diesel_async::{pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection};

pub type DbPool = Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

pub async fn create_pool(connection_string: &str, max_connections: u32) -> Result<DbPool, anyhow::Error> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(connection_string);
    
    let pool = Pool::builder()
        .max_size(max_connections)
        .build(manager)
        .await?;
    
    Ok(pool)
}
