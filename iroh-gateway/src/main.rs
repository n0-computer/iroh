use clap::Parser;
use iroh_gateway::{config::Config, core::Core, metrics};

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, required = false, default_value_t = 9050)]
    port: u16,
    #[clap(short, long)]
    writeable: bool,
    #[clap(short, long)]
    fetch: bool,
    #[clap(short, long)]
    cache: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut config = Config::new(args.writeable, args.fetch, args.cache, args.port);
    config.set_default_headers();
    println!("{:#?}", config);

    iroh_metrics::init(metrics::metrics_config()).expect("failed to initialize metrics");
    metrics::register_counters();

    let handler = Core::new(config);
    handler.serve().await;

    iroh_metrics::shutdown_tracing();
}
