for await (const event of Iroh.subscribe()) {
  if (event.InsertLocal != null) {
    console.log("doc event: InsertLocal", event.InsertLocal.entry.record);
  }
  if (event.InsertRemote != null) {
    console.log("doc event: InsertRemote", event.InsertRemote.entry.record);
  }
}
