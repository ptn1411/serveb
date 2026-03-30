#!/usr/bin/env node

const http = require("http");
const path = require("path");
const fs = require("fs");
const handler = require("serve-handler");

// ---- Parse CLI args ----
const args = process.argv.slice(2);
let port = 3000;
let directory = process.cwd();

for (let i = 0; i < args.length; i++) {
  if ((args[i] === "-p" || args[i] === "--port") && args[i + 1]) {
    port = parseInt(args[i + 1], 10);
    i++;
  } else if (args[i] === "-l" && args[i + 1]) {
    port = parseInt(args[i + 1], 10);
    i++;
  } else if (args[i] === "--help" || args[i] === "-h") {
    console.log(`
  serveb - Static file server with built-in browser UI

  Usage: serveb [directory] [options]

  Options:
    -p, --port <port>   Port to listen on (default: 3000)
    -l <port>           Alias for --port
    -h, --help          Show this help

  Examples:
    serveb                    # Serve current directory
    serveb ./my-files         # Serve specific directory
    serveb -p 8080            # Use custom port
    serveb ./dist --port 5000 # Both options
`);
    process.exit(0);
  } else if (!args[i].startsWith("-")) {
    directory = path.resolve(args[i]);
  }
}

// ---- Load embedded UI ----
const uiPath = path.join(__dirname, "..", "lib", "ui.html");
const uiContent = fs.readFileSync(uiPath, "utf-8");

// ---- Directory listing API ----
function getDirectoryListing(dirPath) {
  const fullPath = path.join(directory, dirPath);

  if (!fullPath.startsWith(directory)) {
    throw new Error("Access denied");
  }

  const entries = fs.readdirSync(fullPath, { withFileTypes: true });
  const items = [];

  for (const entry of entries) {
    const entryPath = path.join(fullPath, entry.name);
    const item = { name: entry.name, isDir: entry.isDirectory() };

    if (!item.isDir) {
      try {
        const stat = fs.statSync(entryPath);
        item.size = stat.size;
        item.mtime = stat.mtime.toISOString();
      } catch {
        item.size = 0;
      }
    }

    items.push(item);
  }

  // Sort: directories first, then files alphabetically
  items.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return items;
}

function requestHandler(req, res) {
  const url = new URL(req.url, `http://localhost`);

  // API: Directory listing
  if (url.pathname === "/__api/list") {
    const dirPath = url.searchParams.get("path") || "/";
    try {
      const items = getDirectoryListing(dirPath);
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      });
      res.end(JSON.stringify({ path: dirPath, items }));
    } catch (err) {
      res.writeHead(err.message === "Access denied" ? 403 : 404, {
        "Content-Type": "application/json",
      });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // UI: Serve browser at root or /__browse
  if (url.pathname === "/" || url.pathname === "/__browse") {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(uiContent);
    return;
  }

  // Everything else: serve-handler (file downloads, static assets)
  return handler(req, res, {
    public: directory,
    directoryListing: false,
    cleanUrls: false,
    trailingSlash: false,
  });
}

function startServer(tryPort) {
  const server = http.createServer(requestHandler);

  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.log(`  ⚠ Port ${tryPort} in use, trying ${tryPort + 1}...`);
      startServer(tryPort + 1);
    } else {
      console.error(err);
      process.exit(1);
    }
  });

  server.listen(tryPort, () => {
    const boxWidth = 44;
    const line = "─".repeat(boxWidth);

    console.log();
    console.log(`  ┌${line}┐`);
    console.log(`  │${"".padStart(boxWidth)}│`);
    console.log(`  │${"  serveb".padEnd(boxWidth)}│`);
    console.log(`  │${"".padStart(boxWidth)}│`);
    console.log(`  │${"  Serving:".padEnd(boxWidth)}│`);
    console.log(`  │${"  " + directory.padEnd(boxWidth - 2)}│`);
    console.log(`  │${"".padStart(boxWidth)}│`);
    console.log(
      `  │${"  Local:  http://localhost:" + tryPort + "/".padEnd(boxWidth - 28 - String(tryPort).length)} │`,
    );
    console.log(`  │${"".padStart(boxWidth)}│`);
    console.log(`  └${line}┘`);
    console.log();
  });
}

startServer(port);
