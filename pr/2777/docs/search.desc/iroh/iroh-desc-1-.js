searchState.loadedDescShard("iroh", 1, "Enable this <code>Client</code> to acknowledge pings.\nClose the connection\nClose the http relay connection.\nDisconnect the http relay connection.\nConnect to a relay Server and returns the underlying relay …\nIs this a known node?\nCreates a new <code>RelayMap</code> with a single relay server …\nCreate an empty relay map.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs the <code>RelayMap</code> from an iterator of <code>RelayNode</code>s.\nReturns a <code>RelayMap</code> from a <code>RelayUrl</code>.\nGet the given node.\nHTTP-specific constants for the relay server and client.\nSkip the verification of the relay server’s SSL …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether or not this <code>Conn</code> is closed.\nReturns <code>true</code> if the underlying relay connection is …\nAre there any nodes in this map?\nIndicate this client is the preferred way to communicate …\nIndicates this client is a prober\nHow many nodes are known?\nThe local address that the <code>Conn</code> is listening on.\nGet the local addr of the connection. If there is no …\nCreate a new <code>ClientBuilder</code>\nReturns an <code>Iterator</code> over all known nodes.\nSends a packet that tells the server whether this …\nLet the server know that this client is the preferred …\nSend a ping to the server. Return once we get an expected …\nSets whether to connect to the relay via websockets or not.\nSet an explicit proxy url to proxy all HTTP(S) traffic …\nThe public key for this client\nReads a message from the server. Returns the message and …\nReturns the relay map for this mode.\nSends a packet to the node identified by <code>dstkey</code>\nSend a packet to the server.\nSend a ping with 8 bytes of random data.\nRespond to a ping request. The <code>data</code> field should be filled …\nSend a pong back to the server.\nA fully-fledged iroh-relay server over HTTP or HTTPS.\nThe expected <code>PublicKey</code> of the relay server we are …\nSets the server url\nWhether this relay server should only be used for STUN …\nThe stun port of the relay server.\nThe <code>RelayUrl</code> where this relay server can be dialed.\nReturns the sorted relay URLs.\nThe received packet bytes.\nIf set, is a description of why the connection is …\nAn advisory duration that the client should wait before …\nThe <code>PublicKey</code> of the packet sender.\nAn advisory duration for how long the client should …\nThe HTTP upgrade protocol used for relaying.\nThe HTTP path under which the relay accepts relaying …\nThe HTTP path under which the relay allows doing latency …\nRelays over the custom relaying protocol with a custom …\nRelays over websockets.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nTries to match the value of an HTTP upgrade header to …\nThe HTTP upgrade header used or expected.\nTLS certificate configuration.\nHandle incoming connections to the Server.\nUse Let’s Encrypt.\nRate limits.\nUse a static TLS key and certificate chain.\nThe main underlying IO stream type used for the relay …\nMetrics tracked for the relay server\nA plain non-Tls <code>tokio::net::TcpStream</code>\nConfiguration for the Relay HTTP and HTTPS server.\nA running Relay + STUN server.\nThe task for a running server actor.\nConfiguration for the full Relay &amp; STUN server.\nConfiguration for the STUN server.\nA Tls wrapped <code>tokio::net::TcpStream</code>\nTLS configuration for Relay server.\nAborts the server.\nAdds a new connection to the server and serves it.\nBurst limit for accepting new connection. Unlimited if not …\nRate limit for accepting new connection. Unlimited if not …\nNumber of connections we have accepted\nThe socket address on which the STUN server should bind.\nBytes received from a <code>FrameType::SendPacket</code>\nBytes sent from a <code>FrameType::SendPacket</code>\nMode for getting a cert.\nCreate a <code>ClientConnHandler</code>, which can verify connections …\nCloses the server and waits for the connections to …\nNumber of accepted ‘iroh derp http’ connection upgrades\n<code>FrameType::SendPacket</code> dropped that are disco messages\n<code>FrameType::SendPacket</code> received that are disco messages\n<code>FrameType::SendPacket</code> sent that are disco messages\nNumber of connections we have removed because of an error\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nNumber of <code>FrameType::Ping</code>s received\nThe socket address the HTTP server is listening on.\nThe socket address on which the Relay HTTP server should …\nThe socket address the HTTPS server is listening on.\nThe socket address on which to serve the HTTPS server.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether or not the relay <code>ServerActorTask</code> is closed.\nRate limits.\nReturns the server metadata cert that can be sent by the …\nSocket to serve metrics on.\nTODO: replace with builder\nPackets of other <code>FrameType</code>s dropped\nPackets of other <code>FrameType</code>s received\nPackets of other <code>FrameType</code>s sent\nReturns the server’s public key.\nConfiguration for the Relay server, disabled if <code>None</code>.\nReturns the server’s secret key.\nThe iroh secret key of the Relay server.\n<code>FrameType::SendPacket</code> dropped, that are not disco messages\n<code>FrameType::SendPacket</code> received, that are not disco messages\n<code>FrameType::SendPacket</code> sent, that are not disco messages\nNumber of <code>FrameType::Pong</code>s sent\nRequests graceful shutdown.\nStarts the server.\nConfiguration for the STUN server, disabled if <code>None</code>.\nThe socket address the STUN server is listening on.\nReturns the handle for the task.\nTLS configuration for the HTTPS server.\nNumber of unique client keys per day\nNumber of <code>FrameType::Unknown</code> received\nNumber of accepted websocket connections\nThe TLS certificate chain.\nConfiguration for Let’s Encrypt certificates.\nThe TLS private key.\nThe <code>AlternateServer</code>atribute\nErrors that can occur when handling a STUN packet.\nThe <code>ErrorCode</code>atribute\nerror response\nThe <code>Fingerprint</code>atribute\nindication\nSTUN request had bogus fingerprint.\nThe STUN message could not be parsed or is otherwise …\nSTUN response has malformed attributes.\nThe <code>MappedAddress</code>atribute\nThe STUN message class. Although there are four message …\nClass used to decode STUN messages\nThe <code>MessageIntegrity</code>atribute\nThe <code>MessageIntegritySha256</code>atribute\nSTUN request didn’t end in fingerprint.\nThe <code>Nonce</code>atribute\nSTUN request is not a binding request when it should be.\nSTUN packet is not a response when it should be.\nThe <code>PasswordAlgorithm</code>atribute\nThe <code>PasswordAlgorithms</code>atribute\nThe <code>Realm</code>atribute\nrequest\nThe <code>Software</code>atribute\nSTUN Attributes that can be attached to a <code>StunMessage</code>\nDescribes an error decoding a <code>StunMessage</code>\nsuccess response\nThe transaction ID is a 96-bit identifier, used to …\nThe <code>Unknown</code>atribute\nThe <code>UnknownAttributes</code>atribute\nThe <code>UserHash</code>atribute\nThe <code>UserName</code>atribute\nThe <code>XorMappedAddress</code>atribute\nReturns a reference to the internal attribute value or an …\nReturns a reference to the bytes that represents the …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns the STUN attribute type of this instance.\nDecodes the STUN raw buffer\nCreates a cryptographically random transaction ID chosen …\nReturns a reference to the <code>AlternateServer</code> attribute.\nReturns a reference to the <code>ErrorCode</code> attribute.\nReturns a reference to the <code>Fingerprint</code> attribute.\nReturns a reference to the <code>MappedAddress</code> attribute.\nReturns a reference to the <code>MessageIntegrity</code> attribute.\nReturns a reference to the <code>MessageIntegritySha256</code> …\nReturns a reference to the <code>Nonce</code> attribute.\nReturns a reference to the <code>PasswordAlgorithm</code> attribute.\nReturns a reference to the <code>PasswordAlgorithms</code> attribute.\nReturns a reference to the <code>Realm</code> attribute.\nReturns a reference to the <code>Software</code> attribute.\nReturns a reference to the <code>Unknown</code> attribute.\nReturns a reference to the <code>UnknownAttributes</code> attribute.\nReturns a reference to the <code>UserHash</code> attribute.\nReturns a reference to the <code>UserName</code> attribute.\nReturns a reference to the <code>XorMappedAddress</code> attribute.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets the context associated to this decoder\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReports whether b is a STUN message.\nReturns true if this <code>StunAttribute</code> is <code>AlternateServer</code>\nReturns true if this <code>StunAttribute</code> is <code>ErrorCode</code>\nReturns true if this <code>StunAttribute</code> is <code>Fingerprint</code>\nReturns true if this <code>StunAttribute</code> is <code>MappedAddress</code>\nReturns true if this <code>StunAttribute</code> is <code>MessageIntegrity</code>\nReturns true if this <code>StunAttribute</code> is …\nReturns true if this <code>StunAttribute</code> is <code>Nonce</code>\nReturns true if this <code>StunAttribute</code> is <code>PasswordAlgorithm</code>\nReturns true if this <code>StunAttribute</code> is <code>PasswordAlgorithms</code>\nReturns true if this <code>StunAttribute</code> is <code>Realm</code>\nReturns true if this <code>StunAttribute</code> is <code>Software</code>\nReturns true if this <code>StunAttribute</code> is <code>Unknown</code>\nReturns true if this <code>StunAttribute</code> is <code>UnknownAttributes</code>\nReturns true if this <code>StunAttribute</code> is <code>UserHash</code>\nReturns true if this <code>StunAttribute</code> is <code>UserName</code>\nReturns true if this <code>StunAttribute</code> is <code>XorMappedAddress</code>\nSTUN Methods Registry\nParses a STUN binding request.\nParses a successful binding response STUN packet. The IP …\nGenerates a binding request STUN packet.\nGenerates a binding response.\nBinding\nReserved\nShared secret\nA drop guard to clean up test infrastructure.\nHandle and drop guard for test DNS and Pkarr servers.\nCreate a DNS resolver with a single nameserver.\nCreate a <code>ConcurrentDiscovery</code> with <code>DnsDiscovery</code> and …\nCreate a <code>DnsResolver</code> configured to use the test DNS server.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe socket address of the DNS server.\nThe node origin domain.\nWait until a Pkarr announce for a node is published to the …\nThe HTTP URL of the Pkarr server.\nRun DNS and Pkarr servers on localhost.\nRuns a relay server with STUN enabled suitable for tests.\nRun DNS and Pkarr servers on localhost with the specified …\nString prefix describing the kind of iroh ticket.\nA token containing information for establishing a …\nA ticket is a serializable object combining information …\nDeserialize from a string.\nCreates a ticket from given addressing info.\nReturns the argument unchanged.\nDeserialize from the base32 string representation bytes.\nCalls <code>U::from(self)</code>.\nCreates a new ticket.\nThe <code>NodeAddr</code> of the provider for this ticket.\nSerialize to string.\nSerialize to bytes used in the base32 string …\nError generating the certificate.\nError creating QUIC config.\nError for generating iroh p2p TLS configs.\nX.509 certificate handling.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreate a TLS client configuration.\nCreate a TLS server configuration.\nAn error that occurs during certificate generation.\nAn X.509 certificate with a libp2p-specific extension is …\nThe contents of the specific libp2p extension, containing …\nAn error that occurs during certificate parsing.\nAn error that occurs during signature verification.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGenerates a self-signed TLS certificate that includes a …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAttempts to parse the provided bytes as a <code>P2pCertificate</code>.\nThe <code>PublicKey</code> of the remote peer.\nVerify the <code>signature</code> of the <code>message</code> signed by the secret …\nBuilder for the <code>Node</code>.\nUse a custom discovery mechanism.\nThe default bind addr of the RPC .\nUse the default discovery mechanism.\nDisable docs completely.\nGarbage collection is disabled.\nConfiguration for node discovery.\nStorage backend for documents.\nPersistent node.\nPolicy for garbage collection.\nGarbage collection is run at the given interval.\nThe quic-rpc server endpoint for the iroh node.\nIn memory\nIn memory node.\nIn-memory storage.\nA server which implements the iroh node.\nUse no node discovery mechanism.\nFile-based persistent storage.\nOn disk persistet, at this location.\nA node that is initialized but not yet spawned.\nHandler for incoming connections.\nThe current status of the RPC endpoint.\nRunning on this port.\nStopped.\nConfiguration for storage.\nHandle an incoming connection.\nRegisters a protocol handler for incoming connections.\nBinds the node service to a specific socket IPv4 address.\nBinds the node service to a specific socket IPv6 address.\nUse a random port for both IPv4 and IPv6.\nConfigure a blob events sender. This will replace the …\nBuilds a node without spawning it.\nReturns a token that can be used to cancel the node.\nCleans up an existing rpc lock\nReturns a client to control this node over an in-memory …\nReturn a client to control this node over an in-memory …\nOptionally set a custom DNS resolver to use for the magic …\nEnables documents support on this node.\nConfigure the default iroh rpc endpoint, on the default …\nConfigure the default iroh rpc endpoint.\nReturns the <code>Endpoint</code> of the node.\nReturns the <code>Endpoint</code> of the node.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nSets the garbage collection policy.\nReturns a protocol handler for an ALPN.\nReturns a protocol handler for an ALPN.\nGet the relay server we are connected to.\nSkip verification of SSL certificates from relay servers\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether to log the SSL pre-master key.\nLoad the current RPC status from the given location.\nThe address on which the node socket is bound.\nConvenience method to get just the addr part of …\nLists the local endpoint of this node.\nReturns a reference to the used <code>LocalPoolHandle</code>.\nReturns a reference to the used <code>LocalPoolHandle</code>.\nReturns a new builder for the <code>Node</code>, by default configured …\nReturns a new builder for the <code>Node</code>, by default configured …\nReturns <code>Some(addr)</code> if an RPC endpoint is running, <code>None</code> …\nSets the node discovery mechanism.\nReturns the <code>PublicKey</code> of the node.\nPersist all node data in the provided directory.\nReturns a new builder for the <code>Node</code>, configured to persist …\nReturns a new builder for the <code>Node</code>, configured to persist …\nRegister a callback for when GC is done.\nSets the relay servers to assist in establishing …\nConfigure rpc endpoint.\nUses the given <code>SecretKey</code> for the <code>PublicKey</code> instead of a …\nCalled when the node shuts down.\nCalled when the node shuts down.\nShutdown the node.\nSpawns the <code>Node</code> in a tokio task.\nSpawns the node and starts accepting connections.\nStore the current rpc status.\nSets a custom <code>TransportConfig</code> to be used by the <code>Endpoint</code>.\nCreates a new builder for <code>Node</code> using the given databases.\nActual connected RPC client.\nThe port we are connected on.\nUtilities for filesystem operations.\nUtilities for working with tokio io\nConfiguration paths for iroh.\nGeneric utilities to track progress of data transfers.\nA data source\nInformation about the content on a path\nThis function converts an already canonicalized path to a …\ntotal number of files in the directory\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nHelper function that translates a key that was derived …\nLoads a <code>SecretKey</code> from the provided file, or stores a …\nReturns blob name for this data source.\nCreates a new <code>DataSource</code> from a <code>PathBuf</code>.\nReturns the path of this data source.\nWalks the directory to get the total size and number of …\nHelper function that creates a document key from a …\nThis function converts a canonicalized relative path to a …\nCreate data sources from a directory.\nCreate data sources from a path.\ntotal size of all the files in the directory\nCreates a new <code>DataSource</code> from a <code>PathBuf</code> and a custom name.\nTodo: gather more information about validation errors. …\nThe data failed to validate\nGeneric io error. We were unable to read the data.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nPath to the node’s file based blob store.\nPath to the console state\nPath to the <code>iroh_docs::AuthorId</code> of the node’s default …\nPath to the iroh-docs document database\nPaths to files or directories used by Iroh.\nPath to store known peer data.\nPath to RPC lock file, containing the RPC port if running.\nPath to the node’s secret key for the …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nGet the path for this <code>IrohPaths</code> by joining the name to a …\nA sender for progress messages.\nA wrapper around <code>AsyncRead</code> which increments a …\nA generic progress event emitter.\nA writer that tries to send the total number of bytes …\nBlock until the message is sent.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIncrements the progress by <em>amount</em>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturn the inner writer\nCreates a new emitter.\nCreate a new <code>ProgressWriter</code> from an inner writer\nCreate a new progress sender.\nCreate a no-op progress sender.\nSend a message\nSets a new total in case you did not now the total up …\nReturns a receiver that gets incremental values.\nTry to send a message.\nWraps an <code>AsyncRead</code> which implicitly calls …")