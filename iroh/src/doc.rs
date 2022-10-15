pub const IROH_LONG_DESCRIPTION: &str = "
Iroh is a next-generation implementation the Interplanetary File System (IPFS).
IPFS is a networking protocol for exchanging content-addressed blocks of
immutable data. 'content-addressed' means referring to data by the hash of it's
content, which makes the reference both unique and verifiable. These two
properties make it possible to get data from any node in the network that speaks
the IPFS protocol, including IPFS content being served by other implementations
of the protocol.

For more info see https://iroh.computer/docs";

pub const STATUS_LONG_DESCRIPTION: &str = "
status reports the current operational setup of iroh. Use status as a go-to
command for understanding where iroh commands are being processed. different
ops configurations utilize different network and service implementations
under the hood, which can lead to varying performance characteristics.

Status reports connectivity, which is either offline or online:

  offline: iroh is not connected to any background process, all commands
           are one-off, any network connections are closed when a command
           completes. Some network duties may be delegated to remote hosts.

  online:  iroh has found a long-running process to issue commands to. Any
           comand issued will be deletegated to the long-running process as a
           remote procedure call

If iroh is online, status also reports the service configuration of the
long running process, including the health of the configured subsystem(s).
Possible configurations fall into two buckets:

  one:     Iroh is running with all services bundled into one single process,
           this setup is common in desktop enviornments.

  cloud:   Iroh is running with services split into separate processes, which
           are speaking to each other via remote procedure calls.

Use the --watch flag to continually poll for changes.

Status reports no metrics about the running system aside from current service
health. Instead all metrics are emitted through uniform tracing collection &
reporting, which is intended to be consumed by tools like prometheus and
grafana. For more info on metrics collection, see
https://iroh.computer/docs/metrics";

pub const GET_LONG_DESCRIPTION: &str = "
Download file or directory specified by <ipfs-path> from IPFS into [path]. If
path already exists and is a file then it's overwritten with the new downloaded
file. If path already exists and is a directory, the command fails with an
error. If path already exists, is a file and the downloaded data is a directory,
that's an error.

By default, the output will be written to the working directory. If no file or
directory name can be derived from the <ipfs-path>, the output will be written
to the given path's CID.

If <ipfs-path> is already present in the iroh store, no network call will
be made.";

pub const P2P_CONNECT_LONG_DESCRIPTION: &str = "
Attempts to open a new direct connection to a peer address. By default p2p
continulously maintains an open set of peer connections based on requests &
internal hueristics. Connect is useful in situations where it makes sense to
manually force libp2p to dial a known peer. A common example includes when you
know the multiaddr or peer ID of a peer that you would like to exchange data
with.

The address format is in multiaddr format. For example:

 > iroh p2p connect /ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ

for more info on multiaddrs see https://iroh.computer/docs/concepts#multiaddr

If a peer ID is provided, connect first perform a distribtued hash table (DHT)
lookup to learn the address of the given peer ID before dialing.";

pub const P2P_LOOKUP_LONG_DESCRIPTION: &str = "
Takes as input a peer ID or address and prints the output of the libp2p-identify
protocol. When provided with a peer ID, the address is looked up on the 
Network's Distributed Hash Table (DHT) before connecting to the node. When 
provided with a multiaddress, the connection is dialed directly.

Providing no <ADDR> argument will return your local node information.";
