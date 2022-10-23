pub const IROH_LONG_DESCRIPTION: &str = "
Iroh is a next-generation implementation the Interplanetary File System (IPFS).
IPFS is a networking protocol for exchanging content-addressed blocks of
immutable data. 'content-addressed' means referring to data by the hash of it's
content, which makes the reference both unique and verifiable. These two
properties make it possible to get data from any node in the network that speaks
the IPFS protocol, including IPFS content being served by other implementations
of the protocol.

For more info see https://iroh.computer/docs";

pub const START_LONG_DESCRIPTION: &str = "
Iroh start kicks off 'daemons' on your local machine: long-running processes 
that make iroh work. Iroh requires a running daemon to do anything meaningful 
like get or add content, and `iroh start` is the fastest way to get iroh up &
running locally

Use the start, stop, and status commands to monitor iroh on your local machine,
and control it's uptime. start runs daemons in the background, so there's no 
need to keep your terminal open after running start. Once running, stop iroh 
with `iroh stop`.

Daemons provide 'services'. Services work together to fullfill requests.
There are three services:

  storage  -  a database of IPFS content
  p2p      -  peer-2-peer networking functionality
  gateway  -  bridge the IPFS network to HTTP

By default iroh start spins up storage & gateway services. Start the p2p service
with `iroh start p2p`.  To learn more about each service, see:
https://iroh.computer/docs/services

Iroh start is by no means the only way to get iroh up & running. Long running 
local deployments should be scheduled by your operating systems daemon 
supervisior, and cloud deployments should invoke daemon binaries directly. 
Regardless of how iroh is started, you can always use `iroh status` to monitor 
service health.
";

pub const STOP_LONG_DESCRIPTION: &str = "
stop turns local iroh services off by killing daemon processes. There are three
iroh services, each backed by a daemon:

   storage  -  a database of IPFS content
   p2p      -  peer-2-peer networking functionality
   gateway  -  bridge the IPFS network to HTTP

By default `iroh stop` attempts to stop all three services. To stop specific
services, provide service names as arguments, eg: `iroh stop p2p`.

When a deamon starts it creates a lockfile and writes it's process identifier 
(PID) to the lock. Iroh stop uses this lock to lookup the process & send an 
interrupt signal to the daemon, which halts the service. Stop will also try to 
clean up any stray lock files in the even that a program crash fails to remove 
the lockfile from the file system.

Stop only works for local processes, and cannot be used to interact with remote
services.
";

pub const STATUS_LONG_DESCRIPTION: &str = "
status reports the current operational setup of iroh. Use status as a go-to
command for understanding where iroh commands are being processed. different
ops configurations utilize different network and service implementations
under the hood, which can lead to varying performance characteristics.

Service status can be in one of four states:

  Down:         The service is not currently running, or is 
                not configured to connect to the proper port.
                
  Serving:      The service is running & healthy
  
  Not Serving:  The service is running, but unhealthy.
  
  Unknown:      The service is in an unknown state. 
                This should not happen.

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
