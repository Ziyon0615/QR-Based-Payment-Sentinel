import { spawn } from "node:child_process";

const children = [
  spawn(process.execPath, ["--watch", "backend/server.mjs"], { stdio: "inherit" }),
  spawn(process.execPath, ["node_modules/next/dist/bin/next", "dev"], {
    stdio: "inherit",
  }),
];

let stopping = false;
function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(exitCode), 300);
}

for (const child of children) {
  child.on("exit", (code) => {
    if (!stopping && code && code !== 0) stop(code);
  });
}

process.on("SIGINT", () => stop(0));
process.on("SIGTERM", () => stop(0));
