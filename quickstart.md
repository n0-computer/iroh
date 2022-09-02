# Quickstart: Gateway

This guide will walk you through running iroh cloud on your local machine, using the default configuration of a gateway backed by a p2p and store service. Once a gateway is up & running we’ll use it to fetch content from the IPFS network by requesting content from a web browser.


⚠️ *The quickstart script currently only works for macOS & linux*


## 1. Run Iroh locally

we’ve prepped a bash file one-liner for you:

```bash
$ curl -fsSL https://sh.iroh.computer/setup.sh | sh -s -- quickstart
```

Running stuff from the internet directly on your terminal is generally a bad idea. Feel free to read through the script first 😄 by dropping the pipe `|` character and everything after it to print `[setup.sh](https://sh.iroh.computer/setup.sh)` to your terminal. The setup script takes a bit of time to fetch precompiled binaries. Once up and running you should see terminal output that looks like this:

```
$ curl -fsSL https://sh.iroh.computer/setup.sh | sh-s--quickstart
Fetching https://vorc.iroh.computer/bin/iroh-gateway/darwin/aarch64/latest
Fetching https://vorc.iroh.computer/bin/iroh-p2p/darwin/aarch64/latest
Fetching https://vorc.iroh.computer/bin/iroh-store/darwin/aarch64/latest
Fetching https://vorc.iroh.computer/bin/iroh-ctl/darwin/aarch64/latest
starting iroh-store.
iroh-store started
view logs at ~/.iroh/log/iroh-store.log
starting iroh-p2p.
iroh-p2p started
view logs at ~/.iroh/log/iroh-p2p.log
starting iroh-gateway.
iroh-gateway started
view logs at ~/.iroh/log/iroh-gateway.log
iroh started
iroh-gateway available at http: //localhost:9050
you can run iroh-ctl from ~/.iroh/bin/iroh-ctl
```


🚧 *currently [setup.sh](https://sh.iroh.computer/setup.sh) writes everything to `$HOME/.iroh`, Iroh cloud will be switching to use [standard directories](https://dirs.dev/) for config, cache, and application data. See [issue #142](https://github.com/n0-computer/iroh/issues/142) for more detail:*

## 2. Using the gateway

Open a web browser and visit [`http://127.0.0.1:9050/ipfs/QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR?filename=test.jpg`](http://127.0.0.1:9050/ipfs/QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR?filename=test.jpg) . If working, you should see a funny looking “cat”. If so, congrats! You’ve used iroh to load something from the public IPFS network. If you reload this page that same content will be served from a local cache instead of hitting the network again. Feel free to experiment with other IPFS content!

## 3. Hello `iroh-ctl`

Run `~/.iroh/bin/iroh-ctl status` to get a summary of the health of your iroh cloud services. You should see something like:

```
~/.iroh/bin/iroh-ctl status
Process     Number    Status
gateway     1/1       Serving
p2p         1/1       Serving
store       1/1       Serving
```

This indicates all three services are running & healthy.

## 4. Stopping iroh

This setup script includes a few options, which you can see by replacing `quickstart` with `-h`:

```bash
$ curl -fsSL https://sh.iroh.computer/setup.sh | sh -s -- -h
iroh quickstart

USAGE:
    ./iroh.sh [COMMANDS] [FLAGS] [OPTIONS]

COMMANDS:
    init          Initialize iroh
    start         Start iroh services
    stop          Stop iroh services
    quickstart    Init iroh and start services

FLAGS:
    -h, --help              Prints help information
```

The help text includes a reference to a `stop` command. Let’s run that:

```bash
$ curl -fsSL https://sh.iroh.computer/setup.sh | sh -s -- stop
```

You should see output looking like this:

```
$ curl -fsSL https://sh.iroh.computer/setup.sh | sh -s -- stop
stopping iroh-gateway...
stopping iroh-p2p...
stopping iroh-store...
```