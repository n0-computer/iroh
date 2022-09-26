async fn main_cli(cli: Cli) -> Result<()> {
    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), cli.cfg.clone()];
    let config = make_config(
        // default
        Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        cli.make_overrides_map(),
    )
    .unwrap();

    let client = Client::new(config.rpc_client).await?;

    let api = Api::new(&client).await?;

    run_cli_command(&api, cli).await
}

#[cfg(test)]
async fn fake_cli(cli: Cli) -> Result<()> {
    let fake = crate::fake::FakeApi::default();
    run_cli_command(&api, cli).await
}