# Using a local iroh-relay

It's easy to set up a iroh-relay that runs locally on your machine.

Using cargo:

```shell
$ cargo run --bin iroh-relay --features="iroh-relay" -- --dev
```

This will bind the iroh-relay to `[::]3340` and run it over HTTP.

To connect to this iroh-relay when doing your normal iroh commands, adjust the iroh configuration file to read:

```toml
# iroh.config.toml:
[[relay_nodes]]
url = "http://localhost:3340"
stun_only = false
stun_port = 3478
```

If you want to give a specific port for the iroh-relay to bind to, you can create a iroh-relay config file and pass that file in using the `--config_path` flag. You need to retain a `secret_key`, so it is recommended to run `iroh-relay --config-path [PATH]` once to generate a secret key and save it to the config file before doing further edits to the file.

To change the port you want to listen on, change the port in the `addr` field:

```
# iroh-relay.toml

secret_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
addr = "[::]:12345"
stun_port = 3478
hostname = "my.relay.network"
enable_stun = true
enable_relay = true
```

Check [the iroh-relay file's](../src/bin/iroh-relay.rs) `Config` struct for documentation on each configuration field.

If you change the local iroh-relay server's configuration, however, be sure to adjust the associated fields in your iroh config as well.

