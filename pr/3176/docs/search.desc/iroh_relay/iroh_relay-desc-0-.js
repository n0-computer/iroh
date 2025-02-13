searchState.loadedDescShard("iroh_relay", 0, "Iroh’s relay is a feature within iroh, a peer-to-peer …\nTracks pings on a single relay connection.\nConfiguration of all the relay servers that can be used.\nInformation on a specific relay server.\nConfiguration for speaking to the QUIC endpoint on the …\nExposes <code>Client</code>, which allows to establish connections to a …\nIs this a known node?\nCreates a new <code>RelayMap</code> with a single relay server …\nReturns the current timeout set for pings.\nDefault values used in the relay.\nDNS resolver\nCreate an empty relay map.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs the <code>RelayMap</code> from an iterator of <code>RelayNode</code>s.\nReturns a <code>RelayMap</code> from a <code>RelayUrl</code>.\nGet the given node.\nHTTP-specific constants for the relay server and client.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAre there any nodes in this map?\nHow many nodes are known?\nCreates a new ping tracker, setting the ping timeout for …\nStarts a new ping.\nReturns an <code>Iterator</code> over all known nodes.\nUpdates the ping tracker with a received pong.\nThe port on which the connection should be bound to.\nProtocols used by the iroh-relay\nCreate a QUIC server that accepts connections for QUIC …\nConfiguration to speak to the QUIC endpoint on the relay …\nA fully-fledged iroh-relay server over HTTP or HTTPS.\nWhether this relay server should only be used for STUN …\nThe stun port of the relay server.\nCancel-safe waiting for a ping timeout.\nThe <code>RelayUrl</code> where this relay server can be dialed.\nReturns the sorted relay URLs.\nA relay client.\nBuild a Client.\nThe send half of a relay client.\nThe receive half of a relay client.\nError for sending messages to the relay server.\nA one-way message from server to client, declaring the …\nAn IO error.\nA one-way empty message from server to client, just to …\nIndicates that the client identified by the underlying …\nRequest from a client or server to reply to the other side …\nSends a ping message to the connected relay server.\nReply to a <code>ReceivedMessage::Ping</code> from a client or server …\nSends a pong message to the connected relay server.\nA protocol error.\nThe messages received from a framed relay stream.\nRepresents an incoming packet.\nMessages we can send to a relay server.\nSend a packet of data to the <code>NodeId</code>.\nA one-way message from server to client, advertising that …\nReturns if we should prefer ipv6 it replaces the …\nEstablishes a new connection to the relay server.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nSkip the verification of the relay server’s SSL …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nIndicates this client is a prober\nSet the capacity of the cache for public keys.\nReturns the local address of the client.\nCreates a client config that trusts any servers without …\nCreate a new <code>ClientBuilder</code>\nSets whether to connect to the relay via websockets or not.\nSet an explicit proxy url to proxy all HTTP(S) traffic …\nSplits the client into a sink and a stream.\nThe received packet bytes.\nIf set, is a description of why the connection is …\nAn advisory duration that the client should wait before …\nThe <code>NodeId</code> of the packet sender.\nAn advisory duration for how long the client should …\nThe default HTTPS port used by the Relay server.\nThe default HTTP port used by the Relay server.\nThe default capacity of the key cache for the relay server.\nThe default metrics port used by the Relay server.\nThe default QUIC port used by the Relay server to accept …\nThe default STUN port used by the Relay server.\nThe DNS resolver used throughout <code>iroh</code>.\nThe n0 testing DNS node origin, for production.\nThe n0 testing DNS node origin, for testing.\nRecord data for a TXT record\nTXT records returned from <code>DnsResolver::lookup_txt</code>\nRemoves all entries from the cache.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nPerform an ipv4 lookup with a timeout.\nResolve IPv4 and IPv6 in parallel with a timeout.\nRace an ipv4 and ipv6 lookup with a timeout in a staggered …\nPerform an ipv4 lookup with a timeout in a staggered …\nPerform an ipv6 lookup with a timeout.\nPerform an ipv6 lookup with a timeout in a staggered …\nLooks up node info by DNS name.\nLooks up node info by DNS name in a staggered fashion.\nLooks up node info by <code>NodeId</code> and origin domain name.\nLooks up node info by <code>NodeId</code> and origin domain name.\nLookup a TXT record.\nCreate a new DNS resolver with sensible cross-platform …\nSupport for handling DNS resource records for dialing by …\nResolve a hostname from a URL to an IP address.\nReturns the raw character strings of this TXT record.\nCreate a new DNS resolver configured with a single UDP DNS …\nThe DNS name for the iroh TXT record.\nError returned when an input value is too long for <code>UserData</code>…\nData about a node that may be published to and resolved …\nExtension methods for <code>NodeId</code> to encode to and decode from …\nInformation about a node that may be published to and …\nThe max byte length allowed for user defined data.\nUnder the hood this is a UTF-8 String that is less than or …\nAdds direct addresses to the node data.\nRemoves all direct addresses from the node data.\nThe information published about the node.\nReturns the direct addresses of the node.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nParses a <code>NodeInfo</code> from a <code>pkarr::SignedPacket</code>.\nParses a <code>NodeInfo</code> from a TXT records lookup.\nParses a <code>NodeId</code> from [<code>z-base-32</code>] encoding.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConverts into a <code>NodeAddr</code> without cloning.\nCreates a new <code>NodeData</code> with a relay URL and a set of …\nCreates a new <code>NodeInfo</code> from its parts.\nConverts into a <code>NodeAddr</code> by cloning the needed fields.\nThe <code>NodeId</code>.\nReturns the relay URL of the node.\nSets the relay URL of the node data.\nSets the user data of the node data.\nCreates a <code>pkarr::SignedPacket</code>.\nConverts into a list of <code>{key}={value}</code> strings.\nEncodes a <code>NodeId</code> in [<code>z-base-32</code>] encoding.\nReturns the optional user-defined data of the node.\nSets the direct addresses and returns the updated node …\nSets the direct addresses and returns the updated node …\nSets the relay URL and returns the updated node data.\nSets the relay URL and returns the updated node info.\nSets the user data.\nSets the user data.\nThe HTTP upgrade protocol used for relaying.\nThe HTTP path under which the relay accepts relaying …\nThe HTTP path under which the relay allows doing latency …\nRelays over the custom relaying protocol with a custom …\nRelays over websockets.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nTries to match the value of an HTTP upgrade header to …\nThe HTTP upgrade header used or expected.\nThis module exports <code>looks_like_disco_wrapper</code> as the only …\nThis module implements the relaying protocol used by the …\nSTUN packets sending and receiving.\nThe 6 byte header of all discovery messages.\nReports whether p looks like it’s a packet containing an …\nThe maximum size of a packet sent over relay. (This only …\nThe <code>AlternateServer</code>atribute\nErrors that can occur when handling a STUN packet.\nThe <code>ErrorCode</code>atribute\nerror response\nThe <code>Fingerprint</code>atribute\nindication\nSTUN request had bogus fingerprint.\nThe STUN message could not be parsed or is otherwise …\nSTUN response has malformed attributes.\nThe <code>MappedAddress</code>atribute\nThe STUN message class. Although there are four message …\nClass used to decode STUN messages\nThe <code>MessageIntegrity</code>atribute\nThe <code>MessageIntegritySha256</code>atribute\nSTUN request didn’t end in fingerprint.\nThe <code>Nonce</code>atribute\nSTUN request is not a binding request when it should be.\nSTUN packet is not a response when it should be.\nThe <code>PasswordAlgorithm</code>atribute\nThe <code>PasswordAlgorithms</code>atribute\nThe <code>Realm</code>atribute\nrequest\nThe <code>Software</code>atribute\nSTUN Attributes that can be attached to a <code>StunMessage</code>\nDescribes an error decoding a <code>StunMessage</code>\nsuccess response\nThe transaction ID is a 96-bit identifier, used to …\nThe <code>Unknown</code>atribute\nThe <code>UnknownAttributes</code>atribute\nThe <code>UserHash</code>atribute\nThe <code>UserName</code>atribute\nThe <code>XorMappedAddress</code>atribute\nReturns a reference to the internal attribute value or an …\nReturns a reference to the bytes that represents the …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns the STUN attribute type of this instance.\nDecodes the STUN raw buffer\nCreates a cryptographically random transaction ID chosen …\nReturns a reference to the <code>AlternateServer</code> attribute.\nReturns a reference to the <code>ErrorCode</code> attribute.\nReturns a reference to the <code>Fingerprint</code> attribute.\nReturns a reference to the <code>MappedAddress</code> attribute.\nReturns a reference to the <code>MessageIntegrity</code> attribute.\nReturns a reference to the <code>MessageIntegritySha256</code> …\nReturns a reference to the <code>Nonce</code> attribute.\nReturns a reference to the <code>PasswordAlgorithm</code> attribute.\nReturns a reference to the <code>PasswordAlgorithms</code> attribute.\nReturns a reference to the <code>Realm</code> attribute.\nReturns a reference to the <code>Software</code> attribute.\nReturns a reference to the <code>Unknown</code> attribute.\nReturns a reference to the <code>UnknownAttributes</code> attribute.\nReturns a reference to the <code>UserHash</code> attribute.\nReturns a reference to the <code>UserName</code> attribute.\nReturns a reference to the <code>XorMappedAddress</code> attribute.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets the context associated to this decoder\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReports whether b is a STUN message.\nReturns true if this <code>StunAttribute</code> is <code>AlternateServer</code>\nReturns true if this <code>StunAttribute</code> is <code>ErrorCode</code>\nReturns true if this <code>StunAttribute</code> is <code>Fingerprint</code>\nReturns true if this <code>StunAttribute</code> is <code>MappedAddress</code>\nReturns true if this <code>StunAttribute</code> is <code>MessageIntegrity</code>\nReturns true if this <code>StunAttribute</code> is …\nReturns true if this <code>StunAttribute</code> is <code>Nonce</code>\nReturns true if this <code>StunAttribute</code> is <code>PasswordAlgorithm</code>\nReturns true if this <code>StunAttribute</code> is <code>PasswordAlgorithms</code>\nReturns true if this <code>StunAttribute</code> is <code>Realm</code>\nReturns true if this <code>StunAttribute</code> is <code>Software</code>\nReturns true if this <code>StunAttribute</code> is <code>Unknown</code>\nReturns true if this <code>StunAttribute</code> is <code>UnknownAttributes</code>\nReturns true if this <code>StunAttribute</code> is <code>UserHash</code>\nReturns true if this <code>StunAttribute</code> is <code>UserName</code>\nReturns true if this <code>StunAttribute</code> is <code>XorMappedAddress</code>\nSTUN Methods Registry\nParses a STUN binding request.\nParses a successful binding response STUN packet. The IP …\nGenerates a binding request STUN packet.\nGenerates a binding response.\nBinding\nReserved\nShared secret\nALPN for our quic addr discovery\nEndpoint close error code\nEndpoint close reason\nHandles the client side of QUIC address discovery.\nReturns the argument unchanged.\nClient side of QUIC address discovery.\nCalls <code>U::from(self)</code>.\nCreate a new QuicClient to handle the client side of QUIC …\nAccess restriction for a node.\nControls which nodes are allowed to use the relay.\nAccess is allowed.\nTLS certificate configuration.\nPer-client rate limit configuration.\nThe default certificate reload interval.\nAccess is denied.\nEveryone\nUse Let’s Encrypt.\nRate limits.\nUse a static TLS key and certificate chain.\nMetrics tracked for the relay server\nConfiguration for the QUIC server.\nConfiguration for the Relay HTTP and HTTPS server.\nUse a TLS key and certificate chain that can be reloaded.\nA Certificate resolver that reloads the certificate every …\nOnly nodes for which the function returns <code>Access::Allow</code>.\nA running Relay + STUN server.\nConfiguration for the full Relay &amp; STUN server.\nConfiguration for the STUN server.\nStunMetrics tracked for the relay server\nTLS configuration for Relay server.\nBurst limit for accepting new connection. Unlimited if not …\nRate limit for accepting new connection. Unlimited if not …\nNumber of connections we have accepted\nAccess configuration.\nNumber of bad requests, either non-stun packets or …\nThe socket address on which the STUN server should bind.\nThe socket address on which the QUIC server should bind.\nMax number of bytes per second to read from the client …\nBytes received from a <code>FrameType::SendPacket</code>\nBytes sent from a <code>FrameType::SendPacket</code>\nMode for getting a cert.\nThe certificates chain if configured with manual TLS …\nRate limits for incoming traffic from a client connection.\nNumber of client connections which have had any frames …\n<code>FrameType::SendPacket</code> dropped that are disco messages\n<code>FrameType::SendPacket</code> received that are disco messages\n<code>FrameType::SendPacket</code> sent that are disco messages\nNumber of connections we have removed because of an error\nNumber of failures\nNumber of frames received from client connection which …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nNumber of <code>FrameType::Ping</code>s received\nThe socket address the HTTP server is listening on.\nThe socket address on which the Relay HTTP server should …\nGet the server’s http <code>RelayUrl</code>.\nThe socket address the HTTPS server is listening on.\nThe socket address on which to serve the HTTPS server.\nGet the server’s https <code>RelayUrl</code>.\nPerform the initial load and construct the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nNumber of successful requests over ipv4\nNumber of successful requests over ipv6\nIs this node allowed?\nKey cache capacity.\nRate limits.\nMax number of bytes to read in a single burst.\nSocket to serve metrics on.\nPackets of other <code>FrameType</code>s dropped\nPackets of other <code>FrameType</code>s received\nPackets of other <code>FrameType</code>s sent\nConfiguration for the QUIC server, disabled if <code>None</code>.\nThe socket address the QUIC server is listening on.\nThe socket address on which to server the QUIC server is …\nConfiguration for the Relay server, disabled if <code>None</code>.\nNumber of accepted ‘iroh derp http’ connection upgrades\nReload the certificate.\nNumber of stun requests made\n<code>FrameType::SendPacket</code> dropped, that are not disco messages\n<code>FrameType::SendPacket</code> received, that are not disco messages\n<code>FrameType::SendPacket</code> sent, that are not disco messages\nNumber of <code>FrameType::Pong</code>s sent\nThe TLS server configuration for the QUIC server.\nThe server configuration.\nShutdown the resolver.\nRequests graceful shutdown.\nStarts the server.\nConfiguration for the STUN server, disabled if <code>None</code>.\nThe socket address the STUN server is listening on.\nReturns the handle for the task.\nExposes functions to quickly configure a server suitable …\nTLS configuration for the HTTPS server.\nNumber of unique client keys per day\nNumber of <code>FrameType::Unknown</code> received\nNumber of accepted websocket connections\nThe TLS certificate chain.\nState for Let’s Encrypt certificates.\nCreates a <code>QuicConfig</code> suitable for testing.\nCreates a <code>RelayConfig</code> suitable for testing.\nCreates a <code>rustls::ServerConfig</code> and certificates suitable …\nCreates a <code>ServerConfig</code> suitable for testing.\nCreates a <code>StunConfig</code> suitable for testing.\nCreates a <code>TlsConfig</code> suitable for testing.")