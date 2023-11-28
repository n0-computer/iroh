self.onmessage = async (e) => {
  console.log("got event");
  
  const { doc } = e.data;

  self.postMessage({});
  
  for await (const event of Iroh.doc_subscribe(doc)) {
    if (event.InsertLocal != null) {
      const entry = event.InsertLocal.entry;
      console.log("doc event: InsertLocal", entry.record);
      const value = await Iroh.blob_get(entry.record.hash);
      console.log("value:", value);
    }

    if (event.InsertRemote != null) {
      console.log("doc event: InsertRemote", event.InsertRemote.entry.record);
    }
  }
}
