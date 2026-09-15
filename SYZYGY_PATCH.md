# Iroh Router 与 Endpoint 关闭完成语义

基线：上游 `v1.2.0` tag，提交 `17c0612f80f78f5288e97b818b1360ae6ea0a51a`。保留完整上游仓库、API、版本和 MIT OR Apache-2.0 许可证。

本仓库作为 Syzygy 的 `crates/patches/iroh` submodule，沿用单一分支 `syzygy/lifecycle-ownership-v1.2.0`；父仓用 gitlink 固定提交，Cargo patch 指向 `crates/patches/iroh/iroh`。`iroh/Cargo.toml` 对 iroh-base、iroh-dns、iroh-relay 使用原发布版本的 registry 依赖，不同时加载上游 sibling path 的副本，保持消费方的公共类型身份与原锁一致。完整上游目录仍保留，补丁与原始上游提交可直接对比。

更新流程：在该分支集成上游和补丁、运行对应 patch 与 Syzygy consumer 验证、推送可获取的 commit，最后更新父仓 gitlink。`git submodule update --init --recursive` 复现已固定的源码；不要在构建时跟随远端分支 HEAD。

`Router::is_shutdown()` 只表示取消 token 已设置。actor 的 DropGuard 在正常退出或 panic 时也设置它；原 `shutdown()` 在此时直接返回 `Ok(())`，跳过仍保存在 Router 内的 JoinHandle。消费方无法通过公开 API 取得这个句柄；在外层先检查 token 也有检查后状态变化的竞态。

Router 改动位于 `iroh/src/protocol.rs` 的 `Router::shutdown`：始终请求取消并 take/await 尚存的任务句柄。Syzygy 的 `NodeRouterV1` 保持单一 owner、只发起一次关闭，等待同一个关闭 future 到真正完成。这里不增加业务逻辑、兼容 API 或新的依赖。

回归位于 `syzygy-net-node-runtime/src/tests`：已取消 actor 的首次关闭传播 JoinError；阻塞协议关闭不能提前报告成功；实际 accept 清退和固定端口释放。消费方验证命令：`cargo test -p syzygy-net-node-runtime -p syzygy-net --all-features --lib`。

Endpoint 改动位于 `iroh/src/socket.rs`、`iroh/src/socket/transports.rs` 与 `iroh/src/socket/transports/ip.rs`。socket actor 是直接生成的任务，不在 noq runtime 的 tracker 内。原 100ms 超时会消费并丢弃唯一 actor handle；现在超时只记录警告，随后继续等待同一任务。保留原 QUIC close / `wait_all_draining` 顺序，再依次等待 socket actor、noq runtime、原生 IP socket 的显式关闭，完成后才设置 `closed`。

IP transport 的底层 `netwatch::UdpSocket` 在 Drop 中只排队 `spawn_blocking`，不会等待 OS close；其 `close().await` 才等待实际关闭工作。Endpoint 在绑定时保留这些 socket 的 Arc，等网络变化 actor 和 QUIC drivers 都退出后再调用显式 close，防止 rebind 重新打开 socket。`EndpointInner` 保存一次具体关闭 future，调用者只借用它等待；取消或并发调用不会丢失 actor join 或已排队的 UDP close job。future 只捕获 socket、noq endpoint、runtime、actor handle 和 IP socket，不捕获 `EndpointInner` 的 Arc。

原生回归位于 `iroh/src/socket/tests/shutdown.rs`：channel 控制的 actor 退出超过 100ms 后仍须等待；取消与并发 close 继续同一操作；`max_blocking_threads(1)` 阻塞真实 UDP close job 时，即使 netwatch 已标记 Closed 也不能提前返回；actor JoinError 仍继续 UDP 关闭。另验证保留 Endpoint 克隆时端口已释放，以及端口被新 owner 占用不影响重复 close 报告自身关闭完成。补丁没有通过探测或重试绑定来判断关闭成功。定向命令：`cargo test --manifest-path crates/patches/iroh/iroh/Cargo.toml --lib socket::tests::shutdown`。还需覆盖 `endpoint::tests`、`socket::tests`、`protocol::tests` 和上述 Syzygy consumer 门禁。

这轮 Endpoint / IP 退出保证针对原生 Tokio 路径；不把 wasm shim 的任务等待或未审计的其它子系统等同于已验证的原生资源关闭。Drop 仍是未完成显式关闭时的紧急中止路径，不代替 `close().await`。

上游最新版核对时间：2026-09-15；1.2.0 与 main 均仍有 early return。待上游实现同等等待保证后恢复 registry 来源。本轮未创建远端 issue 或 PR。

来源：
- https://docs.rs/iroh/1.2.0/iroh/protocol/struct.Router.html#method.shutdown
- https://github.com/n0-computer/iroh/blob/17c0612f80f78f5288e97b818b1360ae6ea0a51a/iroh/src/protocol.rs
- https://docs.rs/iroh/1.2.0/iroh/endpoint/struct.Endpoint.html#method.close
- https://docs.rs/iroh/1.2.0/src/iroh/socket.rs.html
- https://docs.rs/netwatch/0.19.3/netwatch/struct.UdpSocket.html#method.close
- https://docs.rs/netwatch/0.19.3/src/netwatch/udp.rs.html
