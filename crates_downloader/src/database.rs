use crate::config::Config;
use bb8::Pool;
use diesel_async::{AsyncPgConnection, pooled_connection::AsyncDieselConnectionManager};

pub type DbPool = Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

pub struct Database {
    pool: DbPool,
}

impl Database {
    pub async fn new(config: &Config) -> Result<Self, anyhow::Error> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
            config.connection_string.clone(),
        );

        let pool = Pool::builder()
            .max_size(config.max_connections)
            .build(manager)
            .await?;

        Ok(Self { pool })
    }

    pub async fn get_connection(
        &self,
    ) -> Result<
        bb8::PooledConnection<'_, AsyncDieselConnectionManager<AsyncPgConnection>>,
        anyhow::Error,
    > {
        let conn = self.pool.get().await?;
        Ok(conn)
    }

    #[allow(dead_code)]
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }
}
