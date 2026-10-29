// Placeholder webhook agent (Task 12 replaces it). Node stdlib only.
import { createServer } from "node:http";

const port = Number(process.env.PORT || 9000);
createServer((req, res) => {
  if (req.method === "POST" && req.url === "/a2agw/invoke") {
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ text: "placeholder" }));
    });
    return;
  }
  res.writeHead(404).end();
}).listen(port, "0.0.0.0");
