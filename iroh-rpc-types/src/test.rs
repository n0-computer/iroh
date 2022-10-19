#[tarpc::service]
pub trait Test {
    async fn test();
}
