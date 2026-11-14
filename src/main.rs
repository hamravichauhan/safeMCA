#[tokio::main]
async fn main() -> anyhow::Result<()> {
    safemca::run_app().await
}
