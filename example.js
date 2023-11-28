import { other } from "./other.js";

console.log("Iroh says hello to deno!");
const iroh_status = await Iroh.status();
console.log("current status", iroh_status);

other();

console.log("lets get fancy");

const url = new URL("./worker.js", import.meta.url)
const worker = new Worker(url, { type: "module" });

