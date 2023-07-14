use iroh::dial::{dial, Ticket};

#[ffi_export]
/// @memberof iroh_node_t
// TODO(b5): optional token arg
fn iroh_get(
    iroh_node: &mut IrohNode,
    hash: char_p::Ref<'_>,
    peer: char_p::Ref<'_>,
    peer_addr: char_p::Ref<'_>,
    out_path: char_p::Ref<'_>,
    callback: extern "C" fn(Option<repr_c::Box<IrohError>>),
) -> u32 {
    let rt = node.async_runtime();
    node.async_runtime().spawn(async move {
        let result = async move {
            let hash = hash.to_str().parse::<Hash>()?;
            let peer = peer.to_str().parse::<PeerId>()?;
            let peer_addr = peer_addr.to_str().parse()?;
            let conn = node
                .inner()
                .clone()
                .dial(peer, &[peer_addr], &iroh_bytes::protocol::ALPN);
            let out_path = PathBuf::from_str(out_path.to_str()).unwrap();
            get_blob_to_file(conn, hash, None).await
        }
        .await;

        match result {
            Ok() => rt.spawn_blocking(move || callback(None)),
            Err(error) => rt.spawn_blocking(move || callback(Some(IrohError::from(error).into()))),
        };
    });
}

#[ffi_export]
/// @memberof iroh_node_t
/// Get a collection from a peer.
pub fn iroh_get_ticket(
    node: &mut IrohNode,
    ticket: char_p::Ref<'_>,
    out_path: char_p::Ref<'_>,
    callback: extern "C" fn(Option<repr_c::Box<IrohError>>),
) {
    let rt = node.async_runtime();
    node.async_runtime().spawn(async move {
        let result = async {
            let out_path = PathBuf::from_str(out_path.to_str())?;
            // let keypair = node.inner().
            let ticket = Ticket::from_str(ticket.to_str())?;
            // TODO(b5): use the node endpoint(s) to dial
            let conn = node.inner().clone().dial(
                ticket.peer(),
                ticket.addrs(),
                &iroh_bytes::protocol::ALPN,
            );
            get_blob_to_file(conn, ticket.hash(), ticket.token(), out_path).await
        }
        .await;

        match result {
            Ok() => rt.spawn_blocking(move || callback(None)),
            Err(error) => rt.spawn_blocking(move || callback(Some(IrohError::from(error).into()))),
        };
    });
}

async fn get_blob_to_file(
    conn: quinn::Connection,
    hash: Hash,
    token: Option<RequestToken>,
    out_path: PathBuf,
) -> Result<()> {
    get_blob_ranges_to_file(
        conn,
        hash,
        token,
        RangeSpecSeq::new([RangeSet2::all()]),
        out_path,
    )
    .await?
}

// TODO(b5): This currently assumes "all" ranges, needs to be adjusted to honor
// RangeSpecSeq args other than "all"
async fn get_blob_ranges_to_file(
    conn: quinn::Connection,
    hash: Hash,
    token: Option<RequestToken>,
    ranges: RangeSpecSeq,
    out_path: PathBuf,
) -> Result<()> {
    let request = Request::Get(GetRequest::new(hash, RangeSpecSeq::new([RangeSet2::all()])));
    let response = fsm::start(conn, request);
    let connected = response.next().await?;

    let fsm::ConnectedNext::StartRoot(curr) = connected.next().await? else {
                return Ok(None)
            };
    let header = curr.next();

    let path = out_path.clone();
    let mut file = File::create(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
    })
    .await?;

    let (curr, _size) = header.next().await?;
    let _curr = curr.write_all(&mut file).await?;
    file.sync().await?;
    Ok(())
}
