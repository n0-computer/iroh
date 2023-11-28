async function status() {
  return await Deno[Deno.internal].core.ops.op_node_status();
}

async function* subscribe() {
  const sub = await Deno[Deno.internal].core.ops.op_doc_subscribe();
  while (true) {
    const event = await Deno[Deno.internal].core.ops.op_next_doc_event(sub);
    yield event;
  }
}

globalThis.Iroh = { status, subscribe };
