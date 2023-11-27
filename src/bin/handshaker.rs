use clap::Parser;
use shaker::enode::Enode;
use shaker::stream::Stream;
use shaker::Result;
use tracing::{debug, error, info};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
pub struct Cli {
    #[arg(required = true)]
    // Enodes to connect to
    enodes: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Pares CLI arguments
    let cli = Cli::parse();
    // Initialize logger
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();

    for enode in cli.enodes {
        let enode: Enode = enode.try_into()?;
        let mut stream = Stream::connect_with_timeout(enode, Some(2)).await?;
        let hello_message = stream.initiate_handshake().await?;
        info!("👋Received hello message {hello_message:?}");
        match stream.check_shared_capabilities(hello_message) {
            Ok(capabilities) => {
                debug!(
                    "Recipient and initiator share {} capabilities",
                    capabilities.len()
                );
                info!("Capabilities shared are: ");
                for c in capabilities {
                    info!("{c:?}");
                }
            }
            Err(..) => error!("❌Recipient and initiator share no capabilities"),
        }
    }
    Ok(())
}
