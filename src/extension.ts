// sops-lens — VS Code extension that reveals SOPS-encrypted values in-editor.
//
// Three display modes (user-configurable):
//   - codelens     — inline CodeLens above each encrypted line: `[decrypted: <value>]`
//   - hover        — hovering over a line shows the decrypted value in a tooltip
//   - ghost-text   — render the decrypted value as ghost text after the encrypted value
//   - all          — all three at once
//
// Decryption runs the `sops` CLI in a child process. The decrypted plaintext
// is held in memory (per-editor cache), NEVER written to disk.

import * as vscode from 'vscode'
import { spawn } from 'node:child_process'
import * as path from 'node:path'

// ============================================================================
// Detection: is this an encrypted SOPS file?
// ============================================================================

const SOPS_METADATA_MARKER = /^sops:|"sops":\s*{|^\s*sops_version:/m

function isEncryptedSopsFile(doc: vscode.TextDocument): boolean {
  // 1. By filename
  const fname = path.basename(doc.fileName)
  if (fname.endsWith('.enc') || fname.includes('.encrypted.')) return true

  // 2. By content (top of file, first 200 lines)
  const head = doc.getText(new vscode.Range(0, 0, Math.min(doc.lineCount, 200), 0))
  if (SOPS_METADATA_MARKER.test(head)) return true

  // 3. By matching a creation_rules path_regex from a nearby .sops.yaml
  //    (out of scope for v0.1; the marker check above covers most real cases)
  return false
}

// ============================================================================
// Decryption: run sops CLI, parse output into a key-value map
// ============================================================================

interface DecryptedFile {
  /** Map from key name (e.g. "FOO_API_KEY") to decrypted string value. */
  values: Map<string, string>
  /** Lines where each key was found in the ENCRYPTED source. */
  keyLines: Map<string, number>
  /** When this decryption was performed. */
  decryptedAt: number
  /** Error if decryption failed. Empty if ok. */
  error?: string
}

const cache = new Map<string /* doc.uri.toString() */, DecryptedFile>()

/** Spawn sops with the given args + optional stdin input. Resolves with stdout. */
function runSops(bin: string, args: string[], stdin?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true })
    let stdout = ''
    let stderr = ''
    const timeout = setTimeout(() => {
      child.kill()
      reject(new Error('sops timed out after 10s'))
    }, 10_000)
    child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8') })
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8') })
    child.on('error', (err) => { clearTimeout(timeout); reject(err) })
    child.on('close', (code) => {
      clearTimeout(timeout)
      if (code === 0) resolve(stdout)
      else reject(new Error(`sops exited ${code}: ${stderr.slice(0, 500)}`))
    })
    if (stdin !== undefined) {
      child.stdin.write(stdin)
      child.stdin.end()
    }
  })
}

async function decryptDocument(doc: vscode.TextDocument): Promise<DecryptedFile> {
  const cfg = vscode.workspace.getConfiguration('sopsLens')
  const sopsBinary = cfg.get<string>('sopsBinary', 'sops')
  const maxKB = cfg.get<number>('maxFileSizeKB', 512)
  const sizeKB = Buffer.byteLength(doc.getText(), 'utf8') / 1024
  if (sizeKB > maxKB) {
    return { values: new Map(), keyLines: new Map(), decryptedAt: Date.now(), error: `File ${sizeKB.toFixed(0)} KB exceeds maxFileSizeKB=${maxKB}` }
  }

  const inputType = inferInputType(doc)
  // Prefer passing the on-disk path (sops resolves nearby .sops.yaml + age key from there).
  // For unsaved buffers (untitled:), fall back to stdin.
  const useFile = doc.uri.scheme === 'file' && !doc.isDirty
  const args = ['decrypt', '--input-type', inputType, '--output-type', inputType, useFile ? doc.uri.fsPath : '/dev/stdin']

  try {
    const plaintext = await runSops(sopsBinary, args, useFile ? undefined : doc.getText())
    return parsePlaintext(plaintext, doc, inputType)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { values: new Map(), keyLines: new Map(), decryptedAt: Date.now(), error: msg.slice(0, 500) }
  }
}

function inferInputType(doc: vscode.TextDocument): 'yaml' | 'json' | 'dotenv' | 'binary' {
  const fname = path.basename(doc.fileName).toLowerCase()
  if (fname.endsWith('.json') || fname.endsWith('.json.enc')) return 'json'
  if (fname.includes('.env') || fname.endsWith('.dotenv') || fname.endsWith('.dotenv.enc')) return 'dotenv'
  if (fname.endsWith('.yaml') || fname.endsWith('.yml') || fname.endsWith('.yaml.enc') || fname.endsWith('.yml.enc')) return 'yaml'
  // Default to yaml since most sops content is yaml-shaped
  return 'yaml'
}

/**
 * Walk the decrypted plaintext and pair each key with its line number in the
 * ENCRYPTED source. We do this by finding lines that start with `<key>:` (yaml)
 * or `<key>=` (dotenv) in both the plaintext AND the encrypted source.
 */
function parsePlaintext(plaintext: string, doc: vscode.TextDocument, type: 'yaml' | 'json' | 'dotenv' | 'binary'): DecryptedFile {
  const values = new Map<string, string>()
  const keyLines = new Map<string, number>()

  if (type === 'dotenv') {
    // Parse KEY=value lines from plaintext
    for (const line of plaintext.split(/\r?\n/)) {
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/)
      if (m) values.set(m[1]!, m[2]!)
    }
    // Find the line numbers in the encrypted source
    for (let i = 0; i < doc.lineCount; i++) {
      const text = doc.lineAt(i).text
      const m = text.match(/^([A-Za-z_][A-Za-z0-9_]*)=/)
      if (m && values.has(m[1]!)) keyLines.set(m[1]!, i)
    }
  } else if (type === 'json') {
    try {
      const obj = JSON.parse(plaintext)
      flattenObject(obj, '', values)
      // For JSON we can't easily match keys to lines in the encrypted source; fall back to
      // best-effort line matching by quoting each key name.
      for (let i = 0; i < doc.lineCount; i++) {
        const text = doc.lineAt(i).text
        for (const key of values.keys()) {
          const last = key.split('.').pop() ?? key
          if (text.includes(`"${last}"`)) {
            if (!keyLines.has(key)) keyLines.set(key, i)
          }
        }
      }
    } catch {
      // Plaintext wasn't parseable JSON; bail
    }
  } else {
    // yaml — simple line-by-line parse (good enough for top-level keys)
    for (let i = 0; i < plaintext.split(/\r?\n/).length; i++) {
      const line = plaintext.split(/\r?\n/)[i] ?? ''
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/)
      if (m && m[2]) values.set(m[1]!, m[2]!)
    }
    for (let i = 0; i < doc.lineCount; i++) {
      const text = doc.lineAt(i).text
      const m = text.match(/^([A-Za-z_][A-Za-z0-9_-]*):/)
      if (m && values.has(m[1]!)) keyLines.set(m[1]!, i)
    }
  }

  return { values, keyLines, decryptedAt: Date.now() }
}

function flattenObject(obj: unknown, prefix: string, out: Map<string, string>): void {
  if (obj === null || obj === undefined) return
  if (typeof obj !== 'object') {
    out.set(prefix, String(obj))
    return
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => flattenObject(v, `${prefix}[${i}]`, out))
    return
  }
  for (const [k, v] of Object.entries(obj)) {
    flattenObject(v, prefix ? `${prefix}.${k}` : k, out)
  }
}

// ============================================================================
// Truncate for display (don't show 4000-char private keys in full)
// ============================================================================

function truncate(s: string, max = 60): string {
  if (s.length <= max) return s
  return `${s.slice(0, max - 1)}…(${s.length} chars)`
}

// ============================================================================
// CodeLens provider
// ============================================================================

class SopsCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>()
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event
  fire() { this._onDidChangeCodeLenses.fire() }

  async provideCodeLenses(doc: vscode.TextDocument): Promise<vscode.CodeLens[]> {
    const style = vscode.workspace.getConfiguration('sopsLens').get<string>('displayStyle', 'codelens')
    if (style !== 'codelens' && style !== 'all') return []
    if (!isEncryptedSopsFile(doc)) return []

    const decrypted = await ensureDecrypted(doc)
    if (decrypted.error) {
      return [new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
        title: `🔒 SOPS Lens — decrypt failed: ${decrypted.error.slice(0, 100)}`,
        command: '',
      })]
    }

    const lenses: vscode.CodeLens[] = []
    for (const [key, line] of decrypted.keyLines.entries()) {
      const value = decrypted.values.get(key) ?? ''
      lenses.push(new vscode.CodeLens(new vscode.Range(line, 0, line, 0), {
        title: `🔓 ${truncate(value)}`,
        tooltip: `Click to copy ${key}`,
        command: 'sopsLens.copyValue',
        arguments: [value, key],
      }))
    }
    return lenses
  }
}

// ============================================================================
// Hover provider
// ============================================================================

class SopsHoverProvider implements vscode.HoverProvider {
  async provideHover(doc: vscode.TextDocument, pos: vscode.Position): Promise<vscode.Hover | undefined> {
    const style = vscode.workspace.getConfiguration('sopsLens').get<string>('displayStyle', 'codelens')
    if (style !== 'hover' && style !== 'all') return undefined
    if (!isEncryptedSopsFile(doc)) return undefined

    const decrypted = await ensureDecrypted(doc)
    if (decrypted.error) return undefined

    for (const [key, line] of decrypted.keyLines.entries()) {
      if (line === pos.line) {
        const value = decrypted.values.get(key) ?? ''
        const md = new vscode.MarkdownString()
        md.appendCodeblock(`${key} = ${value}`, 'dotenv')
        md.isTrusted = false
        return new vscode.Hover(md, new vscode.Range(line, 0, line, doc.lineAt(line).text.length))
      }
    }
    return undefined
  }
}

// ============================================================================
// Ghost-text decorations
// ============================================================================

const ghostTextDecoration = vscode.window.createTextEditorDecorationType({
  after: {
    color: new vscode.ThemeColor('editorCodeLens.foreground'),
    margin: '0 0 0 1rem',
    fontStyle: 'italic',
  },
})

async function updateGhostTextDecorations(editor: vscode.TextEditor | undefined): Promise<void> {
  if (!editor) return
  const style = vscode.workspace.getConfiguration('sopsLens').get<string>('displayStyle', 'codelens')
  if (style !== 'ghost-text' && style !== 'all') {
    editor.setDecorations(ghostTextDecoration, [])
    return
  }
  if (!isEncryptedSopsFile(editor.document)) {
    editor.setDecorations(ghostTextDecoration, [])
    return
  }
  const decrypted = await ensureDecrypted(editor.document)
  if (decrypted.error) {
    editor.setDecorations(ghostTextDecoration, [])
    return
  }
  const decorations: vscode.DecorationOptions[] = []
  for (const [key, line] of decrypted.keyLines.entries()) {
    const value = decrypted.values.get(key) ?? ''
    const eolPos = new vscode.Position(line, editor.document.lineAt(line).text.length)
    decorations.push({
      range: new vscode.Range(eolPos, eolPos),
      renderOptions: { after: { contentText: `  → ${truncate(value, 80)}` } },
    })
  }
  editor.setDecorations(ghostTextDecoration, decorations)
}

// ============================================================================
// Cache management
// ============================================================================

async function ensureDecrypted(doc: vscode.TextDocument): Promise<DecryptedFile> {
  const key = doc.uri.toString()
  const cached = cache.get(key)
  // Cache entries are valid until the doc is closed or sopsLens.refresh fires.
  if (cached) return cached
  const fresh = await decryptDocument(doc)
  cache.set(key, fresh)
  return fresh
}

function invalidate(uri: vscode.Uri): void {
  cache.delete(uri.toString())
}

// ============================================================================
// Activation
// ============================================================================

let codeLensProvider: SopsCodeLensProvider

export function activate(ctx: vscode.ExtensionContext): void {
  codeLensProvider = new SopsCodeLensProvider()

  ctx.subscriptions.push(
    vscode.languages.registerCodeLensProvider({ scheme: 'file' }, codeLensProvider),
    vscode.languages.registerHoverProvider({ scheme: 'file' }, new SopsHoverProvider()),
    ghostTextDecoration,

    // Commands
    vscode.commands.registerCommand('sopsLens.reveal', async () => {
      const ed = vscode.window.activeTextEditor
      if (!ed) return
      invalidate(ed.document.uri)
      await ensureDecrypted(ed.document)
      codeLensProvider.fire()
      await updateGhostTextDecorations(ed)
    }),
    vscode.commands.registerCommand('sopsLens.hide', () => {
      const ed = vscode.window.activeTextEditor
      if (!ed) return
      invalidate(ed.document.uri)
      codeLensProvider.fire()
      if (ed) ed.setDecorations(ghostTextDecoration, [])
    }),
    vscode.commands.registerCommand('sopsLens.refresh', async () => {
      cache.clear()
      codeLensProvider.fire()
      await updateGhostTextDecorations(vscode.window.activeTextEditor)
    }),
    vscode.commands.registerCommand('sopsLens.copyValue', async (value: string, key: string) => {
      await vscode.env.clipboard.writeText(value)
      vscode.window.setStatusBarMessage(`Copied ${key} (cleared in 30s)`, 30_000)
      setTimeout(() => {
        // best-effort: only clear if clipboard still has our value
        vscode.env.clipboard.readText().then((cur) => {
          if (cur === value) vscode.env.clipboard.writeText('')
        })
      }, 30_000)
    }),

    // Document lifecycle
    vscode.workspace.onDidCloseTextDocument((doc) => invalidate(doc.uri)),
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      invalidate(doc.uri)
      codeLensProvider.fire()
      const ed = vscode.window.visibleTextEditors.find((e) => e.document === doc)
      if (ed) await updateGhostTextDecorations(ed)
    }),
    vscode.window.onDidChangeActiveTextEditor((ed) => updateGhostTextDecorations(ed)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('sopsLens')) {
        cache.clear()
        codeLensProvider.fire()
        updateGhostTextDecorations(vscode.window.activeTextEditor)
      }
    }),
  )

  // Render for any already-open editor on activate
  updateGhostTextDecorations(vscode.window.activeTextEditor)
}

export function deactivate(): void {
  cache.clear()
}
