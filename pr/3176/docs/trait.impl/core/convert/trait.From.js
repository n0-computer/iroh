(function() {
    var implementors = Object.fromEntries([["iroh",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh/endpoint/struct.RemoteInfo.html\" title=\"struct iroh::endpoint::RemoteInfo\">RemoteInfo</a>&gt; for <a class=\"struct\" href=\"iroh/struct.NodeAddr.html\" title=\"struct iroh::NodeAddr\">NodeAddr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh/struct.NodeAddr.html\" title=\"struct iroh::NodeAddr\">NodeAddr</a>&gt; for <a class=\"struct\" href=\"iroh/discovery/struct.DiscoveryData.html\" title=\"struct iroh::discovery::DiscoveryData\">DiscoveryData</a>"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;T&gt; for <a class=\"struct\" href=\"iroh/discovery/struct.ConcurrentDiscovery.html\" title=\"struct iroh::discovery::ConcurrentDiscovery\">ConcurrentDiscovery</a><div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/iter/traits/collect/trait.IntoIterator.html\" title=\"trait core::iter::traits::collect::IntoIterator\">IntoIterator</a>&lt;Item = <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;dyn <a class=\"trait\" href=\"iroh/discovery/trait.Discovery.html\" title=\"trait iroh::discovery::Discovery\">Discovery</a>&gt;&gt;,</div>"]]],["iroh_base",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;(<a class=\"struct\" href=\"iroh_base/struct.PublicKey.html\" title=\"struct iroh_base::PublicKey\">PublicKey</a>, <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"struct\" href=\"iroh_base/struct.RelayUrl.html\" title=\"struct iroh_base::RelayUrl\">RelayUrl</a>&gt;, &amp;[<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/net/socket_addr/enum.SocketAddr.html\" title=\"enum core::net::socket_addr::SocketAddr\">SocketAddr</a>])&gt; for <a class=\"struct\" href=\"iroh_base/struct.NodeAddr.html\" title=\"struct iroh_base::NodeAddr\">NodeAddr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/url/2.5.4/url/parser/enum.ParseError.html\" title=\"enum url::parser::ParseError\">ParseError</a>&gt; for <a class=\"struct\" href=\"iroh_base/struct.RelayUrlParseError.html\" title=\"struct iroh_base::RelayUrlParseError\">RelayUrlParseError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/url/2.5.4/url/struct.Url.html\" title=\"struct url::Url\">Url</a>&gt; for <a class=\"struct\" href=\"iroh_base/struct.RelayUrl.html\" title=\"struct iroh_base::RelayUrl\">RelayUrl</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh_base/struct.NodeAddr.html\" title=\"struct iroh_base::NodeAddr\">NodeAddr</a>&gt; for <a class=\"struct\" href=\"iroh_base/ticket/struct.NodeTicket.html\" title=\"struct iroh_base::ticket::NodeTicket\">NodeTicket</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh_base/struct.PublicKey.html\" title=\"struct iroh_base::PublicKey\">PublicKey</a>&gt; for <a class=\"struct\" href=\"iroh_base/struct.NodeAddr.html\" title=\"struct iroh_base::NodeAddr\">NodeAddr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh_base/struct.RelayUrl.html\" title=\"struct iroh_base::RelayUrl\">RelayUrl</a>&gt; for <a class=\"struct\" href=\"https://docs.rs/url/2.5.4/url/struct.Url.html\" title=\"struct url::Url\">Url</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh_base/ticket/struct.NodeTicket.html\" title=\"struct iroh_base::ticket::NodeTicket\">NodeTicket</a>&gt; for <a class=\"struct\" href=\"iroh_base/struct.NodeAddr.html\" title=\"struct iroh_base::NodeAddr\">NodeAddr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;DecodeError&gt; for <a class=\"enum\" href=\"iroh_base/enum.KeyParsingError.html\" title=\"enum iroh_base::KeyParsingError\">KeyParsingError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;DecodeError&gt; for <a class=\"enum\" href=\"iroh_base/ticket/enum.Error.html\" title=\"enum iroh_base::ticket::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"iroh_base/enum.KeyParsingError.html\" title=\"enum iroh_base::KeyParsingError\">KeyParsingError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"iroh_base/ticket/enum.Error.html\" title=\"enum iroh_base::ticket::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SigningKey&gt; for <a class=\"struct\" href=\"iroh_base/struct.SecretKey.html\" title=\"struct iroh_base::SecretKey\">SecretKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;VerifyingKey&gt; for <a class=\"struct\" href=\"iroh_base/struct.PublicKey.html\" title=\"struct iroh_base::PublicKey\">PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">32</a>]&gt; for <a class=\"struct\" href=\"iroh_base/struct.SecretKey.html\" title=\"struct iroh_base::SecretKey\">SecretKey</a>"]]],["iroh_relay",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"iroh_relay/client/enum.ConnSendError.html\" title=\"enum iroh_relay::client::ConnSendError\">ConnSendError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"iroh_relay/dns/node_info/struct.NodeInfo.html\" title=\"struct iroh_relay::dns::node_info::NodeInfo\">NodeInfo</a>&gt; for NodeAddr"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"iroh_relay/client/enum.ConnSendError.html\" title=\"enum iroh_relay::client::ConnSendError\">ConnSendError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Resolver&lt;GenericConnector&lt;TokioRuntimeProvider&gt;&gt;&gt; for <a class=\"struct\" href=\"iroh_relay/dns/struct.DnsResolver.html\" title=\"struct iroh_relay::dns::DnsResolver\">DnsResolver</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;TxtLookup&gt; for <a class=\"struct\" href=\"iroh_relay/dns/struct.TxtLookup.html\" title=\"struct iroh_relay::dns::TxtLookup\">TxtLookup</a>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[1611,5343,1694]}