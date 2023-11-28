async function status() {
  return await Deno[Deno.internal].core.ops.op_node_status();
}

globalThis.Iroh = { status };
