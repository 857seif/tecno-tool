# Not Techno Tool

A lightweight desktop utility for managing Steam-related scripts and local game libraries.

Built with **Tauri 2** (Rust backend + web frontend).

---

## Features

- **Add** — Install `.lua` scripts by AppID, manage custom providers, drag & drop support
- **Library** — Browse installed games, launch titles, install or remove scripts
- **Settings** — Customize theme colors and background animation speed
- Frameless, resizable window with custom title bar
- Local-only custom providers (no built-in remote sources)

---

## Requirements

- Windows (primary target)
- [Rust](https://www.rust-lang.org/tools/install) (1.77+)
- [Node.js](https://nodejs.org/) (optional, only if you use a frontend build step)
- Tauri CLI:

```bash
cargo install tauri-cli --version "^2"
```

---

## Project Structure

```
├── src/                  # Frontend (HTML / CSS / JS)
│   ├── index.html
│   ├── app.js
│   └── styles.css
└── src-tauri/            # Rust backend
    ├── src/
    │   ├── main.rs
    │   ├── commands.rs
    │   ├── net.rs
    │   ├── providers.rs
    │   ├── steam.rs
    │   ├── util.rs
    │   └── selftest.rs
    ├── capabilities/
    ├── icons/
    ├── Cargo.toml
    └── tauri.conf.json
```

---

## Development

```bash
# From the project root
cargo tauri dev
```

## Build

```bash
cargo tauri build
```

The installer / binary will be produced under `src-tauri/target/release/`.

---

## Custom Providers

You can add your own download sources from the **Add** page.  
A provider URL may contain the `{appid}` placeholder, for example:

```
https://example.com/scripts/{appid}.zip
```

Providers are stored locally and are never mixed with any built-in remote lists.

---

## License

Private / All rights reserved.

