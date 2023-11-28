import { other } from "./other.js";

console.log("Iroh says hello to deno!");
const iroh_status = await Iroh.status();
console.log("current status", iroh_status);

other();

console.log("lets get fancy");

for await (const event of Iroh.subscribe()) {
  if (event.InsertLocal != null) {
    console.log("doc event: InsertLocal", event.InsertLocal.entry.record);
  }
  if (event.InsertRemote != null) {
    console.log("doc event: InsertRemote", event.InsertRemote.entry.record);
  }
}


