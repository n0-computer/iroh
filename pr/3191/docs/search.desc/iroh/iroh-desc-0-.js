searchState.loadedDescShard("iroh", 0, "Peer-to-peer QUIC connections.\nError when decoding.\nThe encoded information had the wrong length.\nError when decoding the public key.\nError when deserialising a <code>PublicKey</code> or a <code>SecretKey</code>.\nThe length of an ed25519 <code>PublicKey</code>, in bytes.\nNetwork-level addressing information for an iroh node.\nThe identifier for a node in the (iroh) network.\nA public key.\nConfiguration of all the relay servers that can be used.\nInformation on a specific relay server.\nA URL identifying a relay server.\nCan occur when parsing a string into a <code>RelayUrl</code>.\nA secret key.\nGet this public key as a byte array.\nIs this a known node?\nCreates a new <code>RelayMap</code> with a single relay server …\nDefault values used in <code>iroh</code>\nReturns the direct addresses of this peer.\nSocket addresses where the peer might be reached directly.\nNode address discovery.\nThis module exports a DNS resolver, which is also the …\nCreate an empty relay map.\nThe <code>Endpoint</code> allows establishing connections to other iroh …\nConvert to a hex string limited to the first 5 bytes for a …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the addressing info from given ticket.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstruct a <code>PublicKey</code> from a slice of bytes.\nCreate a secret key from its byte representation.\nConstructs the <code>RelayMap</code> from an iterator of <code>RelayNode</code>s.\nCreates a new <code>NodeAddr</code> from its parts.\nReturns a <code>RelayMap</code> from a <code>RelayUrl</code>.\nGenerate a new <code>SecretKey</code> with a randomness generator.\nGet the given node.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns true, if only a <code>NodeId</code> is present.\nAre there any nodes in this map?\nHow many nodes are known?\nCo-locating all of the iroh metrics structs\nCreates a new <code>NodeAddr</code> with no <code>relay_url</code> and no …\nThe node’s identifier.\nReturns an <code>Iterator</code> over all known nodes.\nTools for spawning an accept loop that routes incoming …\nReturns the <code>VerifyingKey</code> for this <code>PublicKey</code>.\nThe public key of this <code>SecretKey</code>.\nConfiguration to speak to the QUIC endpoint on the relay …\nReturns the relay url of this peer.\nThe node’s home relay url.\nReturns the <code>SigningKey</code> for this <code>SecretKey</code>.\nSign the given message and return a digital signature\nWhether this relay server should only be used for STUN …\nThe stun port of the relay server.\nInternal utilities to support testing.\nConvert this to the bytes representing the secret part. …\nThe <code>RelayUrl</code> where this relay server can be dialed.\nReturns the sorted relay URLs.\nVerify a signature on a message with this secret key’s …\nWatchable values.\nAdds the given direct addresses.\nAdds a relay url.\nThe default HTTPS port used by the Relay server.\nThe default HTTP port used by the Relay server.\nThe default metrics port used by the Relay server.\nThe default QUIC port used by the Relay server to accept …\nThe default STUN port used by the Relay server.\nProduction configuration.\nStaging configuration.\nHostname of the default Asia-Pacific relay.\nHostname of the default EU relay.\nHostname of the default NA relay.\nGet the default <code>RelayNode</code> for Asia-Pacific\nGet the default <code>RelayNode</code> for EU.\nGet the default <code>RelayNode</code> for NA.\nGet the default <code>RelayMap</code>.\nHostname of the default EU relay.\nHostname of the default NA relay.\nGet the default <code>RelayNode</code> for EU.\nGet the default <code>RelayNode</code> for NA.\nGet the default <code>RelayMap</code>.\nA discovery service that combines multiple discovery …\nNode discovery for <code>super::Endpoint</code>.\nNode discovery results from <code>Discovery</code> services.\nData about a node that may be published to and resolved …\nInformation about a node that may be published to and …\nAdds a <code>Discovery</code> service.\nThe information published about the node.\nDNS node discovery for iroh\nCreates an empty <code>ConcurrentDiscovery</code>.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreates a new <code>ConcurrentDiscovery</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts into a <code>NodeAddr</code> without cloning.\nReturns the optional timestamp when this node info was …\nA discovery service that uses an mdns-like service to …\nCreates a new <code>DiscoveryItem</code> from a <code>NodeInfo</code>.\nReturns the node id of the discovered node.\nThe <code>NodeId</code> of the node this is about.\nReturns the <code>NodeInfo</code> for the discovered node.\nA discovery service which publishes and resolves node …\nReturns the provenance of this discovery item.\nPublishes the given <code>NodeData</code> to the discovery mechanism.\nResolves the <code>DiscoveryItem</code> for the given <code>NodeId</code>.\nA static node discovery to manually add node addressing …\nSubscribe to all addresses that get <em>passively</em> discovered.\nConverts into a <code>NodeAddr</code> by cloning the needed fields.\nDNS node discovery\nThe n0 testing DNS node origin, for production.\nThe n0 testing DNS node origin, for testing.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreates a new DNS discovery using the <code>iroh.link</code> domain.\nCreates a new DNS discovery.\nDiscovery using <code>swarm-discovery</code>, a variation on mdns\nName of this discovery service.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreate a new <code>LocalSwarmDiscovery</code> Service.\nDefault TTL for the records in the pkarr signed packet.\nInterval in which to republish the node info even if …\nThe production pkarr relay run by number 0.\nThe testing pkarr relay run by number 0.\nPublisher of node discovery information to a pkarr relay.\nA pkarr client to publish <code>pkarr::SignedPacket</code>s to a pkarr …\nResolver of node discovery information from a pkarr relay.\nPkarr based node discovery for iroh, supporting both relay …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a pkarr publisher which uses the number 0 pkarr …\nCreates a pkarr resolver which uses the number 0 pkarr …\nCreates a new publisher for the <code>SecretKey</code>.\nCreates a new publisher using the pkarr relay server at …\nCreates a new client.\nPublishes a <code>SignedPacket</code>.\nResolves a <code>SignedPacket</code> for the given <code>NodeId</code>.\nPublishes the addressing information about this node to a …\nCreates a new <code>PkarrPublisher</code> with a custom TTL and …\nBuilder for <code>DhtDiscovery</code>.\nPkarr Mainline DHT and relay server node discovery.\nBuilds the discovery mechanism.\nCreates a new builder for <code>DhtDiscovery</code>.\nExplicitly sets the pkarr client to use.\nSets whether to publish to the Mainline DHT.\nReturns the argument unchanged.\nReturns the argument unchanged.\nSets whether to include the direct addresses in the DNS …\nSets the initial delay before the first publish.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nUses the default number 0 pkarr relay URL.\nSets the pkarr relay URL to use.\nSets the republish delay for the DHT.\nSets the secret key to use for signing the DNS packets.\nSets the time-to-live value for the DNS packets.\nThe provenance string for this discovery implementation.\nA static node discovery to manually add node addressing …\nAugments node addressing information for the given node ID.\nReturns the argument unchanged.\nCreates a static discovery instance from node addresses.\nReturns node addressing information for the given node ID.\nCalls <code>U::from(self)</code>.\nCreates a new static discovery instance.\nRemoves all node addressing information for the given node …\nSets node addressing information for the given node ID.\nThe DNS resolver used throughout <code>iroh</code>.\nThe n0 testing DNS node origin, for production.\nThe n0 testing DNS node origin, for testing.\nRemoves all entries from the cache.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nPerform an ipv4 lookup with a timeout.\nResolve IPv4 and IPv6 in parallel with a timeout.\nRace an ipv4 and ipv6 lookup with a timeout in a staggered …\nPerform an ipv4 lookup with a timeout in a staggered …\nPerform an ipv6 lookup with a timeout.\nPerform an ipv6 lookup with a timeout in a staggered …\nLooks up node info by DNS name.\nLooks up node info by DNS name in a staggered fashion.\nLooks up node info by <code>NodeId</code> and origin domain name.\nLooks up node info by <code>NodeId</code> and origin domain name.\nLookup a TXT record.\nCreate a new DNS resolver with sensible cross-platform …\nSupport for handling DNS resource records for dialing by …\nResolve a hostname from a URL to an IP address.\nCreate a new DNS resolver configured with a single UDP DNS …\nThe DNS name for the iroh TXT record.\nData about a node that may be published to and resolved …\nExtension methods for <code>NodeId</code> to encode to and decode from …\nInformation about a node that may be published to and …\nAdds direct addresses to the node data.\nRemoves all direct addresses from the node data.\nThe information published about the node.\nReturns the direct addresses of the node.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreates a new <code>NodeInfo</code> from its parts.\nParses a <code>NodeInfo</code> from a <code>pkarr::SignedPacket</code>.\nParses a <code>NodeInfo</code> from a TXT records lookup.\nParses a <code>NodeId</code> from [<code>z-base-32</code>] encoding.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts into a <code>NodeAddr</code> without cloning.\nCreates a new <code>NodeData</code> with a relay URL and a set of …\nCreates a new <code>NodeInfo</code> with an empty <code>NodeData</code>.\nThe <code>NodeId</code> of the node this is about.\nReturns the relay URL of the node.\nSets the relay URL of the node data.\nConverts into a <code>NodeAddr</code> by cloning the needed fields.\nCreates a <code>pkarr::SignedPacket</code>.\nConverts into a list of <code>{key}={value}</code> strings.\nEncodes a <code>NodeId</code> in [<code>z-base-32</code>] encoding.\nSets the direct addresses and returns the updated node …\nSets the direct addresses and returns the updated node …\nSets the relay URL and returns the updated node data.\nSets the relay URL and returns the updated node info.\nthe endpoint has reached the confidentiality or integrity …\nthe application or application protocol caused the …\nFuture produced by <code>Endpoint::accept</code>.\nFuture produced by <code>Connection::accept_bi</code>\nFuture produced by <code>Connection::accept_uni</code>\nParameters for controlling the peer’s acknowledgement …\nA key for sealing data with AEAD-based algorithms\nUses all available paths\nApplication layer added the address directly.\nReason given by an application for closing the connection\nThe peer closed the connection\nBuilder for <code>Endpoint</code>.\nthe number of connection IDs provided by the peer exceeds …\nthe server refused to accept a new connection\nreceived more data in CRYPTO frames than can be buffered\nWe received a CallMeMaybe.\nA chunk of data from the receive stream\nThe connection could not be created because not enough of …\nError indicating that a stream has not been opened or has …\nThe stream has already been stopped, finished, or reset\nThe stream has already been finished or reset\nOptions for the <code>Endpoint::connect_with_opts</code> function.\nIn-progress connection attempt future\nA QUIC connection.\nReason given by the transport for closing the connection\nThe peer’s QUIC stack aborted the connection …\nReasons why a connection might be lost\nThe connection was lost\nThe connection was lost\nThe connection was lost\nThe connection was lost\nThe connection was lost\nConnection statistics\nThe type of connection we have to the endpoint.\nThe type of control message we have received.\nCommon interface for different congestion controllers\nConstructs controllers on demand\nGeneric crypto errors\nServer-side configuration for the crypto protocol\nUse a custom relay map.\nUse the default relay map, with production relay servers …\nDirect UDP connection\nA <em>direct address</em> on which an iroh-node might be …\nInformation about a <em>direct address</em>.\nThe type of direct address.\nDatagram support is disabled locally\nDisable relay servers completely.\nThe address was discovered by a discovery service.\nEnvironment variable to force the use of staging relays.\nControls an iroh node, establishing connections with other …\nError returned by Session::export_keying_material.\nreceived a STREAM frame or a RESET_STREAM frame containing …\nreceived more data than permitted in advertised data limits\nreceived a frame that was badly formatted\nThe stream finished before all bytes were read\nNumber of frames transmitted of each frame type\nA pseudo random key for HKDF\nthe endpoint encountered an internal error and cannot …\nreceived an invalid Retry Token in a client Initial\nAttempted an ordered read following an unordered read\nAn incoming connection for which the server has not yet …\nAdaptor to let <code>Incoming</code> be <code>await</code>ed like a <code>Connecting</code>.\nkey update error\nA locally bound socket address.\nThe local application closed the connection\nThe largest representable value\nThe largest encoded value length\nBoth a UDP and a relay connection are used.\nParameters governing MTU discovery.\nthe connection is being closed abruptly in the absence of …\nno viable network path exists\nApplication layer with a specific name added the node …\nWe have no verified connection to this PublicKey\nFuture produced by <code>Connection::open_bi</code>\nFuture produced by <code>Connection::open_uni</code>\ndetected an error with protocol compliance that was not …\nDefines the mode of path selection for all traffic flowing …\nStatistics related to a transmission path\nWe received a Ping from the node.\nWe received a Pong from the node.\nAn address assigned by the router using port mapping.\nAn error occurred during reading\nFuture produced by <code>Connection::read_datagram</code>\nErrors that arise from reading from a stream.\nA read error occurred\nErrors that arise from reading from a stream.\nErrors from <code>RecvStream::read_to_end</code>\nA stream that can only be used to receive data\nRelay connection over relay\nA node communicated with us first via relay.\nConfiguration of the relay servers for an <code>Endpoint</code>.\nForces all traffic to go exclusively through relays\nDetails about a remote iroh node which is known to this …\nThe peer abandoned transmitting data on this stream\nThe peer is unable to continue processing this connection, …\nErrors that arise while waiting for a stream to be reset\nError for attempting to retry an <code>Incoming</code> which already …\nreceived a frame for a stream identifier that exceeded …\nreceived a frame for a stream that was not in a state that …\nAddress was loaded from the fs.\nErrors that can arise when sending a datagram\nA stream that can only be used to send data\nParameters governing incoming connections\nThe origin or <em>source</em> through which an address associated …\nUse the staging relay servers from n0.\nThe peer is no longer accepting data on this stream\nErrors that arise while monitoring for a send stream stop …\nIdentifier for a stream within a particular connection\nPublic internet address discovered via STUN.\nHard NAT: STUN’ed IPv4 address + local fixed port.\nreceived transport parameters that were badly formatted, …\nCommunication with the peer has lapsed for longer than the …\nThe datagram is larger than the connection can currently …\nThe stream is larger than the user-supplied limit\nParameters governing the core QUIC state machine\nTransport-level errors occur when a peer violates the …\nThe peer violated the QUIC specification as understood by …\nTransport-level error code\nA node communicated with us first via UDP.\nStatistics about UDP datagrams transmitted or received on …\nNot yet determined..\nThe peer does not support receiving datagram frames\nError indicating that the specified QUIC version is not …\nAn integer less than 2^62\nThe peer doesn’t implement any supported version\nA handle to some connection internals, use with care.\nErrors that arise from writing to a stream\nIndicates how many bytes and chunks had been transferred …\nFuture that completes when a connection is fully …\nThis was a 0-RTT stream and the server rejected it\nThis was a 0-RTT stream and the server rejected it\nThis was a 0-RTT stream and the server rejected it\nThis was a 0-RTT stream and the server rejected it\nAccepts an incoming connection on the endpoint.\nAttempts to accept this incoming connection (an error may …\nAccept the next incoming bidirectional stream.\nAccepts the next incoming uni-directional stream.\nAccepts this incoming connection using a custom …\nThe ack-eliciting threshold we will request the peer to use\nSpecifies the ACK frequency config (see <code>AckFrequencyConfig</code> …\nAdds a discovery mechanism for this endpoint.\nInforms this <code>Endpoint</code> about addresses of the iroh node.\nInforms this <code>Endpoint</code> about addresses of the iroh node, …\nThe UDP address reported by the remote node.\nThe address.\nThe addresses at which this node might be reachable.\nDerive AEAD using hkdf\nWhether the implementation is permitted to set the spin …\nExtracts the ALPN protocol from the peer’s handshake …\nExtracts the ALPN protocol from the peer’s handshake …\nSets the ALPN protocols that this endpoint will accept on …\nBinds the magic endpoint.\nSets the IPv4 bind address.\nSets the IPv6 bind address.\nSpecifies the amount of time that MTU discovery should …\nThe number of times a black hole was detected in the path\nReturns the local socket addresses on which the underlying …\nConstruct a fresh <code>Controller</code>\nReturns the builder for an <code>Endpoint</code>, with a production …\nThe contents of the chunk\nThe total amount of bytes which have been transferred …\nThe amount of bytes which had been written\nThe amount of full chunks which had been written\nRemoves all discovery services from the builder.\nDuplicate the controller’s state\nCloses the QUIC endpoint and the magic socket.\nCloses the connection immediately.\nIf the connection is closed, the reason why.\nWait for the connection to be closed for any reason.\nType of error\nHow to construct new <code>congestion::Controller</code>s\nCongestion events on the connection\nCurrent state of the congestion control algorithm, for …\nReturns a <code>Watcher</code> that reports the current connection type …\nThe type of connection we have to the node, either direct …\nConnects to a remote <code>Endpoint</code>.\nStarts a connection attempt with a remote <code>Endpoint</code>.\nCreate QUIC error code from TLS alert code\nTLS configuration used for incoming connections\nMaximum quantity of out-of-order crypto layer data to …\nLargest UDP payload size the path currently supports\nCurrent congestion window of the connection\nMaximum number of incoming application datagram bytes to …\nMaximum number of outgoing application datagram bytes to …\nBytes available in the outgoing datagram buffer.\nThe amount of UDP datagrams observed\nReturns the default relay mode.\nWhich directions data flows in\nReturns a <code>Watcher</code> for the direct addresses of this <code>Endpoint</code>…\nOptionally sets a discovery mechanism for this endpoint.\nReturns the discovery mechanism, if configured.\nConfigures the endpoint to also use the mainline DHT with …\nConfigures the endpoint to also use local network …\nConfigures the endpoint to use the default n0 DNS …\nOptionally sets a custom DNS resolver to use for this …\nReturns the DNS resolver used in this <code>Endpoint</code>.\nWhether to use “Generic Segmentation Offload” to …\nClass of error as encoded in the specification\nApplication-specific reason code\nDerives keying material from this connection’s TLS …\nNotify the peer that no more data will ever be written to …\nReturns <code>true</code> if the use of staging relays is forced.\nFrame type that triggered the error\nStatistics about frames received on a connection\nStatistics about frames transmitted on a connection\nType of frame that caused the close\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstruct a <code>VarInt</code> infallibly\nSucceeds iff <code>x</code> &lt; 2^62\nCreate a VarInt without ensuring it’s in range\nParameters negotiated during the handshake\nParameters negotiated during the handshake.\nWhether there is a possible known network path to the …\nReturns a <code>Watcher</code> for the <code>RelayUrl</code> of the Relay server …\nGet the identity of this stream\nGet the identity of this stream\nIgnores this incoming connection attempt, not sending any …\nMaximum number of received bytes to buffer for each …\nMaximum number of received bytes to buffer for all <code>Incoming</code>\nDistinguishes streams of the same initiator and …\nCreate the initial set of keys given the client’s …\nThe initial value to be used as the maximum UDP payload …\nThe RTT used before an RTT sample is taken\nInitial congestion window\nWhich side of a connection initiated the stream\nSkip verification of SSL certificates from relay servers\nSpecifies the time to wait after completing MTU discovery …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts this <code>Connecting</code> into a 0-RTT or 0.5-RTT …\nReturns Self for use in down-casting to extract …\nGet the <code>Incoming</code>\nExtract the integer value\nThe amount of I/O operations executed\nCheck if this stream has been opened during 0-RTT.\nReturns <code>true</code> if the <code>Connection</code> associated with this handle …\nCheck if this endpoint is still alive, or already closed.\nPeriod of inactivity before sending a keep-alive packet\nEnables saving the TLS pre-master key for connections.\nOptionally set a list of known nodes.\nElapsed time since this network path was known to exist.\nLast control message received by this node about this …\nElapsed time since the last payload message was received …\nGet the duration since the last activity we received from …\nTime elapsed time since last we have sent to or received …\nThe latency to the remote node over this network path.\nThe latency of the current network path to the remote node.\nReturns the local IP address which was used when the peer …\nThe amount of bytes lost on this path\nThe amount of packets lost on this path\nThe amount of PLPMTUD probe packets lost on this path …\nCreates a <code>ServerConfig</code> with the given secret key and …\nThe <code>max_ack_delay</code> we will request the peer to use\nMaximum number of incoming bidirectional streams that may …\nVariant of <code>max_concurrent_bidi_streams</code> affecting …\nComputes the maximum size of datagrams that may be passed …\nMaximum duration of inactivity to accept before timing out …\nMaximum number of <code>Incoming</code> to allow to exist at a time\nWhether to allow clients to migrate to new addresses\nThe maximum UDP payload size guaranteed to be supported by …\nSpecifies the minimum MTU change to stop the MTU discovery …\nSpecifies the MTU discovery config (see <code>MtuDiscoveryConfig</code> …\nNotifies the system of potential network changes.\nResets path-specific state.\nCreate a default config with a particular handshake token …\nCreate a new StreamId\nInitializes new connection options.\nReturns the current <code>NodeAddr</code> for this endpoint.\nReturns the node id of this endpoint.\nThe globally unique identifier for this node.\nThe offset in the stream\nPacket deliveries were confirmed\nPackets were deemed lost or marked congested\nPackets are acked in batches, all with the same <code>now</code> …\nThe known MTU for the current network path has been updated\nOne or more packets were just sent\nMethod for opening a sealed message <code>data</code>\nInitiates a new outgoing bidirectional stream.\nInitiates a new outgoing unidirectional stream.\nMaximum reordering in packet number space before FACK …\nStatistics related to the current transmission path\nThis implies we only use the relay to communicate and do …\nCryptographic identity of the peer.\nNumber of consecutive PTOs after which network is …\nAttempts to read from the stream into buf.\nAttempt to write bytes from buf into the stream.\nThe preferred IPv4 address that will be communicated to …\nThe preferred IPv6 address that will be communicated to …\nGet the priority of the send stream\nSets the proxy url from the environment, in this order:\nSets an explicit proxy url to proxy all HTTP(S) traffic …\nRead data contiguously from the stream.\nRead the next segment of data\nRead the next segments of data\nReceives an application datagram.\nRead an exact number of bytes contiguously from the stream.\nConvenience method to read all remaining data into a buffer\nHuman-readable reason for the close\nHuman-readable reason for the close\nHuman-readable explanation of the reason\nWhether to receive observed address reports from other …\nMaximum number of bytes the peer may transmit across all …\nCompletes when the stream has been reset by the peer or …\nRejects this incoming connection attempt.\nReturns the relay map for this mode.\nSets the relay servers to assist in establishing …\nRelay server information, if available.\nReturns the peer’s UDP address.\nWhether the socket address that is initiating this …\nReturns information about the remote node identified by a …\nReturns information about all the remote nodes this …\nReturns the <code>NodeId</code> from the peer’s TLS certificate.\nThe reordering threshold we will request the peer to use\nClose the send stream immediately.\nResponds with a retry packet.\nGenerate the integrity tag for a retry packet\nDuration after a retry token was issued for which it’s …\nCurrent best estimate of this connection’s latency …\nCurrent best estimate of this connection’s latency …\nSaturating integer addition. Computes self + rhs, …\nMethod for sealing message <code>data</code>\nSets a secret key to authenticate with other peers.\nReturns the secret_key of this endpoint.\nTransmits <code>data</code> as an unreliable, unordered application …\nWhether to implement fair queuing for send streams having …\nWhether to send observed address reports to peers.\nMaximum number of bytes to transmit to a peer without …\nThe amount of packets sent on this path\nThe amount of PLPMTUD probe packets sent on this path …\nSets the list of accepted ALPN protocols.\nModifies the number of bidirectional streams that may be …\nModifies the number of unidirectional streams that may be …\nSet the priority of the send stream\nSee <code>quinn_proto::TransportConfig::receive_window</code>.\nReturns a deduplicated list of <code>Source</code>s merged from all …\nA <code>HashMap</code> of <code>Source</code>s to <code>Duration</code>s.\nA stable identifier for this connection.\nStart a server session with this configuration\nReturns connection statistics.\nStop accepting data\nCompletes when the peer stops the stream or reads the …\nMaximum number of bytes the peer may transmit without …\nObject to get current <code>SystemTime</code>\nMaximum reordering in time space before time based loss …\nPrivate key used to authenticate data included in …\nTransport configuration to use for incoming connections\nSet a custom <code>TransportConfig</code>\nSets a custom <code>quinn::TransportConfig</code> for this endpoint.\nSucceeds iff <code>x</code> &lt; 2^62\nSucceeds iff <code>x</code> &lt; 2^62\nSucceeds iff <code>x</code> &lt; 2^62\nThe origin of this direct address.\nStatistics about UDP datagrams received on a connection\nStatistics about UDP datagrams transmitted on a connection\nSpecifies the upper bound to the max UDP payload size that …\nConfiguration for sending and handling validation tokens\nSet a custom <code>ValidationTokenConfig</code>\nNumber of ack-eliciting bytes that may be in flight\nCreate a server config with the given <code>crypto::ServerConfig</code>\nCreate a server config with the given certificate chain to …\nSets the QUIC transport config options for this connection.\nWrite bytes to the stream\nConvenience method to write an entire buffer to the stream\nConvenience method to write an entire list of chunks to …\nConvenience method to write a single chunk in its entirety …\nWrite chunks to the stream\nThe name of the discovery service that discovered the …\nThe name of the application that added the node\nEnum of metrics for the module\nEnum of metrics for the module\nEnum of metrics for the module\nMetrics tracked for the relay server\nNumber of connections we have accepted\nBytes received from a <code>FrameType::SendPacket</code>\nBytes sent from a <code>FrameType::SendPacket</code>\nNumber of connections with a successful handshake that …\nNumber of connections with a successful handshake.\nNumber of client connections which have had any frames …\n<code>FrameType::SendPacket</code> dropped that are disco messages\n<code>FrameType::SendPacket</code> received that are disco messages\n<code>FrameType::SendPacket</code> sent that are disco messages\nNumber of connections we have removed because of an error\nNumber of frames received from client connection which …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nNumber of <code>FrameType::Ping</code>s received\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nNumber of nodes we have attempted to contact.\nNumber of nodes we have managed to contact directly.\nThe number of direct connections we have made to peers.\nThe number of direct connections we have lost to peers.\nThe number of connections to peers we have added over …\nThe number of connections to peers we have removed over …\nPackets of other <code>FrameType</code>s dropped\nPackets of other <code>FrameType</code>s received\nPackets of other <code>FrameType</code>s sent\nNumber of QUIC datagrams received.\nNumber of datagrams received using GRO\nNumber of accepted ‘iroh derp http’ connection upgrades\n<code>FrameType::SendPacket</code> dropped, that are not disco messages\n<code>FrameType::SendPacket</code> received, that are not disco messages\n<code>FrameType::SendPacket</code> sent, that are not disco messages\nNumber of <code>FrameType::Pong</code>s sent\nNumber of unique client keys per day\nNumber of <code>FrameType::Unknown</code> received\nNumber of accepted websocket connections\nHandler for incoming connections.\nThe built router.\nBuilder for creating a <code>Router</code> for accepting protocols.\nHandle an incoming connection.\nConfigures the router to accept the <code>ProtocolHandler</code> when …\nCreates a new <code>Router</code> using given <code>Endpoint</code>.\nReturns the <code>Endpoint</code> stored in this router.\nReturns the <code>Endpoint</code> of the node.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nChecks if the router is already shutdown.\nCreates a new router builder using given <code>Endpoint</code>.\nCalled when the node shuts down.\nShuts down the accept loop cleanly.\nSpawns an accept loop and returns a handle to it …\nA drop guard to clean up test infrastructure.\nHandle and drop guard for test DNS and Pkarr servers.\nCreate a <code>ConcurrentDiscovery</code> with <code>DnsDiscovery</code> and …\nCreate a <code>DnsResolver</code> configured to use the test DNS server.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe socket address of the DNS server.\nThe node origin domain.\nWait until a Pkarr announce for a node is published to the …\nThe HTTP URL of the Pkarr server.\nRun DNS and Pkarr servers on localhost.\nRuns a relay server with STUN and QUIC enabled suitable …\nRuns a relay server.\nRuns a relay server with STUN enabled suitable for tests.\nRun DNS and Pkarr servers on localhost with the specified …\nThe error for when a <code>Watcher</code> is disconnected from its …\nFuture returning the current or next value that’s <code>Some</code> …\nFuture returning the next item after the current one in a …\nA wrapper around a value that notifies <code>Watcher</code>s when the …\nAn observer for a value.\nA stream for a <code>Watcher</code>’s next values.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the currently stored value.\nReturns the currently held value.\nReturns a future completing once the value is set to <code>Some</code> …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a <code>Watchable</code> initialized to given value.\nSets a new value.\nReturns a stream which will yield the most recent values …\nReturns a stream which will yield the most recent values …\nReturns a future completing with <code>Ok(value)</code> once a new …\nCreates a <code>Watcher</code> allowing the value to be observed, but …")