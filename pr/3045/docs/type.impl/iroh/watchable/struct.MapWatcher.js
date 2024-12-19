(function() {
    var type_impls = Object.fromEntries([["iroh",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-MapWatcher%3CW,+T,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#302-310\">Source</a><a href=\"#impl-Clone-for-MapWatcher%3CW,+T,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;W: <a class=\"trait\" href=\"iroh/watchable/trait.Watcher.html\" title=\"trait iroh::watchable::Watcher\">Watcher</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/function/trait.Fn.html\" title=\"trait core::ops::function::Fn\">Fn</a>(W::<a class=\"associatedtype\" href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" title=\"type iroh::watchable::Watcher::Value\">Value</a>) -&gt; T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"iroh/watchable/struct.MapWatcher.html\" title=\"struct iroh::watchable::MapWatcher\">MapWatcher</a>&lt;W, T, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#303-309\">Source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; Self</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","iroh::endpoint::NodeAddrWatcher"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-MapWatcher%3CW,+T,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#295\">Source</a><a href=\"#impl-Debug-for-MapWatcher%3CW,+T,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;W: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"iroh/watchable/trait.Watcher.html\" title=\"trait iroh::watchable::Watcher\">Watcher</a>, T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/function/trait.Fn.html\" title=\"trait core::ops::function::Fn\">Fn</a>(W::<a class=\"associatedtype\" href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" title=\"type iroh::watchable::Watcher::Value\">Value</a>) -&gt; T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"iroh/watchable/struct.MapWatcher.html\" title=\"struct iroh::watchable::MapWatcher\">MapWatcher</a>&lt;W, T, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#295\">Source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","iroh::endpoint::NodeAddrWatcher"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Watcher-for-MapWatcher%3CW,+T,+F%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#312-334\">Source</a><a href=\"#impl-Watcher-for-MapWatcher%3CW,+T,+F%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;W: <a class=\"trait\" href=\"iroh/watchable/trait.Watcher.html\" title=\"trait iroh::watchable::Watcher\">Watcher</a>, T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/function/trait.Fn.html\" title=\"trait core::ops::function::Fn\">Fn</a>(W::<a class=\"associatedtype\" href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" title=\"type iroh::watchable::Watcher::Value\">Value</a>) -&gt; T&gt; <a class=\"trait\" href=\"iroh/watchable/trait.Watcher.html\" title=\"trait iroh::watchable::Watcher\">Watcher</a> for <a class=\"struct\" href=\"iroh/watchable/struct.MapWatcher.html\" title=\"struct iroh::watchable::MapWatcher\">MapWatcher</a>&lt;W, T, F&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Value\" class=\"associatedtype trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#313\">Source</a><a href=\"#associatedtype.Value\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" class=\"associatedtype\">Value</a> = T</h4></section></summary><div class='docblock'>The type of value that can change. <a href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#315-317\">Source</a><a href=\"#method.get\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#tymethod.get\" class=\"fn\">get</a>(&amp;self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::<a class=\"associatedtype\" href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" title=\"type iroh::watchable::Watcher::Value\">Value</a>, <a class=\"struct\" href=\"iroh/watchable/struct.Disconnected.html\" title=\"struct iroh::watchable::Disconnected\">Disconnected</a>&gt;</h4></section></summary><div class='docblock'>Returns the current state of the underlying value, or errors out with\n<a href=\"iroh/watchable/struct.Disconnected.html\" title=\"struct iroh::watchable::Disconnected\"><code>Disconnected</code></a>, if one of the underlying <a href=\"iroh/watchable/struct.Watchable.html\" title=\"struct iroh::watchable::Watchable\"><code>Watchable</code></a>s has been dropped.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.poll_updated\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#319-333\">Source</a><a href=\"#method.poll_updated\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#tymethod.poll_updated\" class=\"fn\">poll_updated</a>(\n    &amp;mut self,\n    cx: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/task/wake/struct.Context.html\" title=\"struct core::task::wake::Context\">Context</a>&lt;'_&gt;,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/task/poll/enum.Poll.html\" title=\"enum core::task::poll::Poll\">Poll</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self::<a class=\"associatedtype\" href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" title=\"type iroh::watchable::Watcher::Value\">Value</a>, <a class=\"struct\" href=\"iroh/watchable/struct.Disconnected.html\" title=\"struct iroh::watchable::Disconnected\">Disconnected</a>&gt;&gt;</h4></section></summary><div class='docblock'>Polls for the next value, or returns <a href=\"iroh/watchable/struct.Disconnected.html\" title=\"struct iroh::watchable::Disconnected\"><code>Disconnected</code></a> if one of the underlying\nwatchables has been dropped.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.updated\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#136-138\">Source</a><a href=\"#method.updated\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#method.updated\" class=\"fn\">updated</a>(&amp;mut self) -&gt; <a class=\"struct\" href=\"iroh/watchable/struct.WatchNextFut.html\" title=\"struct iroh::watchable::WatchNextFut\">WatchNextFut</a>&lt;'_, Self&gt; <a href=\"#\" class=\"tooltip\" data-notable-ty=\"WatchNextFut&lt;&#39;_, Self&gt;\">ⓘ</a></h4></section></summary><div class='docblock'>Returns a future completing with <code>Ok(value)</code> once a new value is set, or with\n<a href=\"iroh/watchable/struct.Disconnected.html\" title=\"struct iroh::watchable::Disconnected\"><code>Err(Disconnected)</code></a> if the connected <a href=\"iroh/watchable/struct.Watchable.html\" title=\"struct iroh::watchable::Watchable\"><code>Watchable</code></a> was dropped. <a href=\"iroh/watchable/trait.Watcher.html#method.updated\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.initialized\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#146-158\">Source</a><a href=\"#method.initialized\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#method.initialized\" class=\"fn\">initialized</a>&lt;T&gt;(&amp;mut self) -&gt; <a class=\"struct\" href=\"iroh/watchable/struct.WatchInitializedFut.html\" title=\"struct iroh::watchable::WatchInitializedFut\">WatchInitializedFut</a>&lt;'_, T, Self&gt; <a href=\"#\" class=\"tooltip\" data-notable-ty=\"WatchInitializedFut&lt;&#39;_, T, Self&gt;\">ⓘ</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"iroh/watchable/trait.Watcher.html\" title=\"trait iroh::watchable::Watcher\">Watcher</a>&lt;Value = <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;T&gt;&gt;,</div></h4></section></summary><div class='docblock'>Returns a future completing once the value is set to <a href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.Some\" title=\"variant core::option::Option::Some\"><code>Some</code></a> value. <a href=\"iroh/watchable/trait.Watcher.html#method.initialized\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.stream\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#173-181\">Source</a><a href=\"#method.stream\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#method.stream\" class=\"fn\">stream</a>(self) -&gt; <a class=\"struct\" href=\"iroh/watchable/struct.WatcherStream.html\" title=\"struct iroh::watchable::WatcherStream\">WatcherStream</a>&lt;Self&gt;<div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Unpin.html\" title=\"trait core::marker::Unpin\">Unpin</a>,</div></h4></section></summary><div class='docblock'>Returns a stream which will yield the most recent values as items. <a href=\"iroh/watchable/trait.Watcher.html#method.stream\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.stream_updates_only\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#197-205\">Source</a><a href=\"#method.stream_updates_only\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#method.stream_updates_only\" class=\"fn\">stream_updates_only</a>(self) -&gt; <a class=\"struct\" href=\"iroh/watchable/struct.WatcherStream.html\" title=\"struct iroh::watchable::WatcherStream\">WatcherStream</a>&lt;Self&gt;<div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Unpin.html\" title=\"trait core::marker::Unpin\">Unpin</a>,</div></h4></section></summary><div class='docblock'>Returns a stream which will yield the most recent values as items, starting from\nthe next unobserved future value. <a href=\"iroh/watchable/trait.Watcher.html#method.stream_updates_only\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.map\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#208-217\">Source</a><a href=\"#method.map\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#method.map\" class=\"fn\">map</a>&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a>, F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/function/trait.Fn.html\" title=\"trait core::ops::function::Fn\">Fn</a>(Self::<a class=\"associatedtype\" href=\"iroh/watchable/trait.Watcher.html#associatedtype.Value\" title=\"type iroh::watchable::Watcher::Value\">Value</a>) -&gt; T&gt;(\n    self,\n    map: F,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"struct\" href=\"iroh/watchable/struct.MapWatcher.html\" title=\"struct iroh::watchable::MapWatcher\">MapWatcher</a>&lt;Self, T, F&gt;, <a class=\"struct\" href=\"iroh/watchable/struct.Disconnected.html\" title=\"struct iroh::watchable::Disconnected\">Disconnected</a>&gt;</h4></section></summary><div class='docblock'>Maps this watcher with a function that transforms the observed values.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.or\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/iroh/watchable.rs.html#221-223\">Source</a><a href=\"#method.or\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"iroh/watchable/trait.Watcher.html#method.or\" class=\"fn\">or</a>&lt;W: <a class=\"trait\" href=\"iroh/watchable/trait.Watcher.html\" title=\"trait iroh::watchable::Watcher\">Watcher</a>&gt;(self, other: W) -&gt; <a class=\"struct\" href=\"iroh/watchable/struct.OrWatcher.html\" title=\"struct iroh::watchable::OrWatcher\">OrWatcher</a>&lt;Self, W&gt;</h4></section></summary><div class='docblock'>Returns a watcher that updates every time this or the other watcher\nupdates, and yields both watcher’s items together when that happens.</div></details></div></details>","Watcher","iroh::endpoint::NodeAddrWatcher"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[16984]}