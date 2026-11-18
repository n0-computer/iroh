# Relay recovery patch for iroh-proxy

Originally written on top of iroh 1.0.3 (`f2eb930dda3779c6d852b72f3712aacd6e573ab1`)
as prekucki/iroh `b61fa39a76e0f22d2db21c9eb2f77e6df7a8de0d`. This branch ports it
onto golemfactory/iroh `main` (iroh 1.5.0, `2c12bb58`).

Upstream has since fixed parts of it on its own, and the port keeps upstream's
versions: answering priority messages during reconnect backoff (#4444,
`sleep_backoff`) and draining relay tasks with `join_next` so shutdown does
not panic on a cancelled task (#4460). The port adds to them: the backoff wait
also drains the normal control inbox, and the shutdown drain is bounded.

Production changes are confined to `iroh/src/socket/transports/relay/actor.rs`:

- Limit graceful relay close to 3 seconds and allow cancellation to interrupt it.
- Limit control enqueueing and route-query enqueueing/replies to 5 seconds.
  Abort actors whose control operations fail, retain their handles until their
  tasks finish, and recreate the home relay after reaping. Other relays are
  recreated on demand.
- Continue answering control requests during reconnect backoff and interrupt
  backoff on cancellation. An ordinary network outage is not a stuck actor.
- Bound the asynchronous interface-snapshot wait to 5 seconds. Skip that check
  on timeout rather than assuming there are no valid local addresses.
- Allow 5 seconds for graceful child shutdown, then abort and reap remaining
  tasks. Already-cancelled tasks must not cause shutdown to panic.

The endpoint identity and wire protocol are unchanged. Async timeouts cannot
interrupt synchronous code that never yields. These fixes address unbounded
waits consistent with the reported production symptoms; they do not establish
the precise cause of that incident.

## Verification

```bash
cargo fmt --check
rustfmt --edition 2024 --check iroh/src/socket/transports/relay/recovery_tests.rs
cargo clippy --locked -p iroh --lib --tests -- -D warnings
cargo test --locked -p iroh --lib socket::transports::relay::actor::tests
```

The added `relay_recovery` tests cover stalled close, control-queue saturation,
route enqueue/reply deadlines, backoff cancellation, shutdown races and forced
shutdown, and datagram exchange after replacing an unresponsive home relay.
They use a local relay and do not depend on a public relay service.

Consumers should pin a reviewed commit. If overriding crates.io dependencies
in an existing application, select the same revision for `iroh`, `iroh-base`,
`iroh-dns`, and `iroh-relay` to keep the workspace's path dependencies and
registry consumers on the same crate identities.

Retire this branch when a reviewed upstream version provides equivalent
recovery behavior and passes these regression tests.
