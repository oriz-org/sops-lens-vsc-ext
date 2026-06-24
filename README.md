# sops-lens-vsc-ext

> VS Code extension that **reveals SOPS-encrypted file values in-editor** as CodeLens / hover tooltip / ghost-text decorations. Decrypts via the `sops` CLI in-memory. **Never writes plaintext to disk.**

## What it does

Open any SOPS-encrypted file (`.env.enc`, `secrets.yaml`, `secrets.json`, anything with a `sops:` metadata block) and the extension renders the decrypted values next to their encrypted ciphertext, in your chosen display style.

You read your secrets at a glance. You never type `sops -d` again. The plaintext never lands on disk.

## Why

- **No disk leak** — the standard workflow `sops -d .env.enc > .env` writes the plaintext to disk for the duration of editing. SOPS Lens skips that step entirely; plaintext lives only in the editor process's memory, gone on file close or VS Code exit.
- **No terminal echo** — `sops decrypt --stdout` prints the secret to your terminal scrollback. SOPS Lens never does that.
- **No git accidents** — there's no `.env` file to accidentally `git add .` into the next commit.

## Display modes

Configurable via `sopsLens.displayStyle`:

| Mode | What it looks like |
|---|---|
| `codelens` (default) | Inline CodeLens above each key: `🔓 dummy-value-123` — click to copy |
| `hover` | Hover over the key line → tooltip shows `KEY = decrypted_value` |
| `ghost-text` | Ghost text after the encrypted value: `FOO_API_KEY: ENC[AES256...] → dummy-value` |
| `all` | All three simultaneously |

## Requirements

- `sops` binary on PATH (or set `sopsLens.sopsBinary` to its absolute path).
- Your sops setup (age key, .sops.yaml, etc.) configured so that `sops -d <file>` works in a terminal. The extension just calls that command.

## Install

**From source (until published to Marketplace):**

```bash
git clone https://github.com/oriz-org/sops-lens-vsc-ext.git
cd sops-lens-vsc-ext
npm install
npm run compile
npm run package    # produces sops-lens-0.1.0.vsix
code --install-extension sops-lens-0.1.0.vsix
```

**Once published**: search `SOPS Lens` in the VS Code extensions marketplace.

## Configuration

```jsonc
{
  // How to display decrypted values
  "sopsLens.displayStyle": "codelens",   // codelens | hover | ghost-text | all

  // Path to the sops binary. Defaults to "sops" (must be on PATH).
  "sopsLens.sopsBinary": "sops",

  // Auto-decrypt on file open. Set false to require manual "SOPS Lens: Reveal" command.
  "sopsLens.decryptOnOpen": true,

  // Skip decryption for files larger than this (KB) — defense against accidentally
  // running sops on a giant binary.
  "sopsLens.maxFileSizeKB": 512
}
```

## Commands

| Command | What it does |
|---|---|
| `SOPS Lens: Reveal` | Force-decrypt the active file + render |
| `SOPS Lens: Hide` | Clear cache for active file + hide decorations |
| `SOPS Lens: Refresh` | Re-decrypt everything (after editing keys / rotating) |
| `SOPS Lens: Copy decrypted value` | Used by CodeLens click — copies to clipboard, auto-clears after 30 s |
| `SOPS Lens: Edit decrypted (virtual view)` | **NEW v0.2** — opens decrypted plaintext in a virtual editor; never on disk |
| `SOPS Lens: Save virtual (re-encrypt)` | **NEW v0.2** — re-encrypts the virtual view back to the source .enc file via sops |

## Editing encrypted files

There's a `✏️ Edit decrypted (virtual view)` CodeLens at the top of every detected encrypted file. Click it OR run `SOPS Lens: Edit decrypted (virtual view)`:

1. A new editor opens with the decrypted plaintext. The URI scheme is `sops-lens-edit://` so VS Code marks it as untitled / unsaved.
2. Edit normally.
3. Run `SOPS Lens: Save virtual (re-encrypt)` to write back. The extension re-encrypts the edited plaintext via `sops encrypt` and atomically replaces the source `.enc` file.
4. Any open editor showing the source file auto-reverts from disk; CodeLens / hover / ghost-text refresh to the new values.

**Plaintext never touches disk** — the virtual document lives only in memory. The `.tmp` file used for atomic replace contains only the freshly-encrypted ciphertext, then is renamed to the source path.

## How it decides a file is encrypted

In order:
1. Filename ends in `.enc` or contains `.encrypted.`
2. File contents have a `sops:` / `"sops":` / `sops_version:` metadata marker in the first 200 lines
3. **NEW v0.2** — A nearby `.sops.yaml` (walked up from the file's directory, max 20 levels) has a `creation_rules` entry whose `path_regex` or `path_glob` matches the file's relative path

If none match, the extension does nothing. No performance cost on regular files.

## Supported encrypted file formats

- **YAML** (`.yaml.enc`, `.yml.enc`, or `.yaml` with a sops block) — line-by-line key/value parse
- **JSON** (`.json.enc`) — flattened key paths (e.g. `database.password`)
- **dotenv** (`.env.enc`, `.dotenv.enc`) — `KEY=VALUE` line parse
- **NEW v0.2: Binary** (`.bin.enc`, `.binary.enc`, or `.enc` files without a sops-yaml marker) — read-only blob preview. UTF-8 text shown when printable; otherwise hex head + byte count. Click to copy the full decoded blob.

## Security caveats

- Plaintext lives in the **VS Code extension host process memory** for the editor session. A core dump of VS Code while a file is open would expose it. Standard secret-management trade-off.
- Clipboard copy auto-clears after **30 seconds** (best-effort — if you copy something else in between, the timer leaves the new clipboard alone).
- The extension **never writes plaintext to disk**. The only on-disk trace is `sops` CLI's own temp files (which it creates + deletes during its own decryption pipeline — out of our control).
- If your `.sops.yaml` lists multiple age recipients, the extension uses whichever age key is available in the standard `SOPS_AGE_KEY_FILE` / `SOPS_AGE_KEY` env (your normal sops setup).

## License

MIT. See [LICENSE](./LICENSE).

## Cross-refs in the oriz family

- [`oriz-org/secrets`](https://github.com/oriz-org/secrets) — the private family secrets store this extension makes pleasant to browse
- [`oriz-org/workspace`](https://github.com/oriz-org/workspace) — umbrella, see `knowledge/services/security/sops.md` and `knowledge/services/security/age.md` for the broader stack
