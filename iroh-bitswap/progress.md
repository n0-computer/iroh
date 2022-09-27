# Porting go-bitswap 

## General Steps

- [ ] (1) Implement everything sync, not libp2p integration
  - [x] Server
  - [ ] Client
- [ ] (2) Integrate with libp2p
  - [x] Server
  - [ ] Client
- [ ] (3) Make async what is needed/where it makes sense
  - [ ] Server
  - [ ] Client

## Source Files

- [x] `./bitswap.go` (181)

### Client

- [ ] `./client/client.go` (479)
- [ ] `./client/stat.go` (30)
- [x] `./client/wantlist/wantlist.go` (142)

- [ ] `./client/internal/getter/getter.go` (138)
- [ ] `./client/internal/blockpresencemanager/blockpresencemanager.go` (121)

- [x] `./client/internal/messagequeue/messagequeue.go` (843)
- [ ] `./client/internal/messagequeue/donthavetimeoutmgr.go` (398)

- [x] `./client/internal/peermanager/peerwantmanager.go` (464)
- [x] `./client/internal/peermanager/peermanager.go` (246)

- [ ] `./client/internal/session/sessionwants.go` (193)
- [ ] `./client/internal/session/cidqueue.go` (63)
- [ ] `./client/internal/session/peerresponsetracker.go` (70)
- [ ] `./client/internal/session/sentwantblockstracker.go` (33)
- [ ] `./client/internal/session/session.go` (508)
- [ ] `./client/internal/session/sessionwantsender.go` (766)

- [ ] `./client/internal/sessionmanager/sessionmanager.go` (196)
- [ ] `./client/internal/sessionpeermanager/sessionpeermanager.go` (150)
- [ ] `./client/internal/sessioninterestmanager/sessioninterestmanager.go` (201)
- [ ] `./client/internal/providerquerymanager/providerquerymanager.go` (430)
- [ ] `./client/internal/notifications/notifications.go` (139)





### Server 

- [x] `./server/server.go` (536)
- [x] `./server/forward.go` (14)
    - skip, legacy
- [x] `./server/internal/decision/engine.go` (1026)
- [x] `./server/internal/decision/blockstoremanager.go` (149)
- [x] `./server/internal/decision/ewma.go` (5)
- [x] `./server/internal/decision/taskmerger.go` (87)
- [x] `./server/internal/decision/ledger.go` (46)
- [x] `./server/internal/decision/scoreledger.go` (353)
- [x] `./server/internal/decision/peer_ledger.go` (46)

### Network

- [x] `./network/connecteventmanager.go` (218)
  - will be tracked inside the ConnectionHandler
- [x] `./network/internal/default.go` (23)
  - just the list of supported protocols
- [ ] `./network/ipfs_impl.go` (472)
  - mostly ConnectionHandler & interface
- [x] `./network/interface.go` (111)
  - not really needed
- [x] `./network/options.go` (22)
  - not needed

### Message

- [x] `./message/message.go` (500)
- [x] `./message/pb/cid.go` (44)
- [x] `./message/pb/message.pb.go` (1569)

### Other

- [ ] `./internal/defaults/defaults.go` (27)
  - default values for the config
- [ ] `./options.go` (79)
  - list of options
- [ ] `./metrics/metrics.go` (46)


  - list of metrics
- [x] `./internal/tracing.go` (13)
  - not needed, skipping
- [x] `./tracer/tracer.go` (13)
  - not needed, skipping
- [x] `./decision/forward.go` (12)
  - deprecated, skipping
- [x] `./sendOnlyTracer.go` (20)
  - not needed, skipping
- [x] `./forward.go` (17)
  - deprecated, skipping
- [x] `./wantlist/forward.go` (23)
  - deprecated, skipping

## Dependencies

- [x] https://github.com/ipfs/go-peertaskqueue (will be ported to `bitswap::peer_task_queue`)
  - [x] `./peertaskqueue.go` (346)
  - [x] `./peertaskqueue_test.go` (340)
  - [x] `./peertask/peertask.go` (81)
  - [x] `./peertracker/peertracker.go` (378)
  - [x] `./peertracker/peertracker_test.go` (720)


## Tests

### Unit Tests

Will be ported as it makes sense.

### Testnet

This would definitely be useful to port for correctness testing, but likely needs a lot of changes.

