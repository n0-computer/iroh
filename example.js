import { other } from "./other.js";

console.log("Iroh says hello to deno!");
const iroh_status = await Iroh.status();
console.log("current status", iroh_status);

other();

console.log("lets get fancy");

const doc = await Iroh.doc_create();
console.log("created doc",);

const url = new URL("./worker.js", import.meta.url)
const worker = new Worker(url, { type: "module" });

console.log("sending doc to worker");
worker.postMessage({
  doc: doc,
});

worker.addEventListener("message", (msg) => {
  console.log("inserting from main thread");
  
  for (let i = 0; i < 10; i++) {
    Iroh.doc_set(doc, `hello-${i}`, `world-${i}`);
  }
})

