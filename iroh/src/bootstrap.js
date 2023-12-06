
async function node_status() {
  return await Deno[Deno.internal].core.ops.op_node_status();
}

async function doc_open(id) {
  return await Deno[Deno.internal].core.ops.op_doc_open(id);
}

async function* doc_subscribe(doc) {
  const sub = await Deno[Deno.internal].core.ops.op_doc_subscribe(doc);
  while (true) {
    const event = await Deno[Deno.internal].core.ops.op_next_doc_event(sub);
    yield event;
  }
}

async function doc_get(doc, key) {
  return await Deno[Deno.internal].core.ops.op_doc_get(doc, key);
}

async function doc_create() {
  return await Deno[Deno.internal].core.ops.op_doc_create();
}

async function doc_set(doc, key, value) {
  return await Deno[Deno.internal].core.ops.op_doc_set(doc, key, value);
}

async function doc_set_hash(doc, key, hash, size) {
  return await Deno[Deno.internal].core.ops.op_doc_set_hash(doc, key, hash, size);
}

async function blob_set(hash, data) {
  return await Deno[Deno.internal].core.ops.op_blob_set(hash, data);
}

async function blob_get(hash) {
  return await Deno[Deno.internal].core.ops.op_blob_get(hash);
}

globalThis.Iroh = {
  node_status, 

  doc_subscribe, 
  doc_create, 
  doc_open, 
  doc_set, 
  doc_set_hash,
  doc_get,

  blob_get,
  blob_set
};
