# Using a local derper

It's easy to set up a derper that runs locally on your machine.

Using cargo:

```shell
$ cargo run --bin derper --features="derper" -- --dev
```

This will bind the derper to `[::]334` and run it over HTTP.

To connect to this derper when doing your normal iroh commands, adjust the iroh configuration file to read:

```toml
# iroh.config.toml:
[[derp_regions]]
region_id = 65535 
avoid = false
region_code = "local"

[[derp_regions.nodes]]
name = "local-default-1"
region_id = 65535 
url = "http://localhost:3340"
stun_only = false
stun_port = 3478
ipv6 = "TryDns"

[derp_regions.nodes.ipv4]
Some = "127.0.0.1"
```

If you want to give a specific port for the derper to bind to, you can create a derper config file and pass that file in using the `--config_path` flag. You need to retain a `secret_key`, so it is recommended to run `derper --config-path [PATH]` once to generate a private key and save it to the config file before doing further edits to the file.

To change the port you want to listen on, change the port in the `addr` field:

```
# derper.toml

secret_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
addr = "[::]:12345"
stun_port = 3478
hostname = "my.derp.network"
enable_stun = true
enable_derp = true
```

Check [the derper file's](../src/bin/derper.rs) `Config` struct for documentation on each configuration field.

If you change the local derper's configuration, however, be sure to adjust the associated fields in your iroh config as well.

