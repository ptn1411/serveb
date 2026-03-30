# bserve

> Static file server with a beautiful built-in file browser UI.

A lightweight CLI tool that serves any directory with a modern, dark-themed file browser interface. Built on top of [`serve-handler`](https://github.com/vercel/serve-handler).

![bserve](https://img.shields.io/npm/v/bserve?style=flat-square&color=7c6af7)

## Features

- 📂 **Beautiful UI** — Dark-themed file browser with icons, filters, and search
- 🗂️ **Directory navigation** — Click folders to browse, breadcrumbs to jump back
- ⬇️ **File downloads** — Click any file to download
- 🔍 **Search & filter** — Filter by file type (mp4, txt, etc.)
- 📊 **Stats bar** — See folder count, file count, total size at a glance
- 🔄 **Auto port** — If port is in use, automatically tries the next one
- ⚡ **Zero config** — Just run `bserve` in any directory

## Install

```bash
npm install -g bserve
```

## Usage

```bash
# Serve current directory
bserve

# Serve a specific directory
bserve ./my-files

# Use a custom port
bserve -p 8080

# Combine options
bserve ./dist --port 5000
```

Then open `http://localhost:3000/` in your browser.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --port <port>` | Port to listen on | `3000` |
| `-l <port>` | Alias for `--port` | `3000` |
| `-h, --help` | Show help | — |

## How it works

`bserve` creates a simple HTTP server with three routes:

| Route | Purpose |
|-------|---------|
| `/` | Serves the built-in file browser UI |
| `/__api/list?path=/` | JSON API for directory listings |
| `/*` | File downloads (powered by `serve-handler`) |

## License

MIT
