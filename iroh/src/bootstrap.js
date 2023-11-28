async function status() {
  return await Deno[Deno.internal].core.ops.op_node_status();
}

async function* doc_subscribe(doc) {
  const sub = await Deno[Deno.internal].core.ops.op_doc_subscribe(doc);
  while (true) {
    const event = await Deno[Deno.internal].core.ops.op_next_doc_event(sub);
    yield event;
  }
}

async function doc_create() {
  return await Deno[Deno.internal].core.ops.op_doc_create();
}

async function doc_set(doc, key, value) {
  return await Deno[Deno.internal].core.ops.op_doc_set(doc, key, value);
}

async function blob_get(hash) {
  return await Deno[Deno.internal].core.ops.op_blob_get(hash);
}

globalThis.Iroh = { status, doc_subscribe, doc_create, doc_set, blob_get };
