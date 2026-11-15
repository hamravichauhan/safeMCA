#[tokio::main]
async fn main() -> anyhow::Result<()> {
    safemcp::run_app().await
}
