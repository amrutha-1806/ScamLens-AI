const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const frontendDir = "C:\\Users\\revan\\Desktop\\threat-view-ai";
const logsDir = "C:\\Users\\revan\\Desktop\\Intellingent scam and phishing detection system\\logs";

const outFile = fs.openSync(path.join(logsDir, "launcher_frontend.out.log"), "a");
const errFile = fs.openSync(path.join(logsDir, "launcher_frontend.err.log"), "a");

const viteBin = path.join(frontendDir, "node_modules", "vite", "bin", "vite.js");

const child = spawn(
  process.execPath,
  [viteBin, "dev", "--host", "127.0.0.1", "--port", "5173"],
  {
    cwd: frontendDir,
    stdio: ["pipe", outFile, errFile],
    windowsHide: true,
  }
);

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
