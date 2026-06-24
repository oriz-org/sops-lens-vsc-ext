// sops-lens — VS Code extension that reveals SOPS-encrypted values in-editor.
//
// v0.2 features (this commit):
//   - 3 display modes: codelens, hover, ghost-text, all
//   - In-memory decryption via the sops CLI; plaintext never written to disk
//   - .sops.yaml creation_rules matching (walks up from the file to find nearest .sops.yaml)
//   - Binary sops file preview (read-only)
//   - "Edit in virtual view" command: opens decrypted plaintext in a virtual document,
//     save re-encrypts back to disk via sops --set

import * as vscode from 'vscode'
import { spawn } from 'node:child_process'
import * as path from 'node:path'
import * as fs from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'

// ============================================================================
// Detection: is this an encrypted SOPS file?
// ============================================================================

const SOPS_METADATA_MARKER = /^sops:|"sops":\s*{|^\s*sops_version:/m

function isEncryptedSopsFile(doc: vscode.TextDocument): boolean {
  const fname = path.basename(doc.fileName)
  if (fname.endsWith('.enc') || fname.includes('.encrypted.')) return true
  const head = doc.getText(new vscode.Range(0, 0, Math.min(doc.lineCount, 200), 0))
  if (SOPS_METADATA_MARKER.test(head)) return true
  if (matchesSopsYamlRules(doc)) return true
  return false
}

/** Walk up from the document's directory looking for the nearest .sops.yaml.
 *  If found, parse its creation_rules and return true if the doc's path matches one. */
function matchesSopsYamlRules(doc: vscode.TextDocument): boolean {
  if (doc.uri.scheme !== 'file') return false
  const filePath = doc.uri.fsPath
  let dir = path.dirname(filePath)
  const root = path.parse(dir).root
  for (let i = 0; i < 20 && dir !== root; i++) {
    const candidate = path.join(dir, '.sops.yaml')
    if (existsSync(candidate)) {
      try {
        const content = readFileSync(candidate, 'utf8')
        return matchesAnyCreationRule(content, filePath, dir)
      } catch {
        return false
      }
    }
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return false
}

/** Parse a .sops.yaml's creation_rules (just path_regex / path_glob entries) and check match.
 *  Lightweight regex over YAML — no full yaml-parse. Good enough because creation_rules is shallow. */
function matchesAnyCreationRule(sopsYaml: string, filePath: string, sopsYamlDir: string): boolean {
  const re = /^\s*-?\s*(path_regex|path_glob):\s*['"]?(.+?)['"]?\s*$/gm
  const relPath = path.relative(sopsYamlDir, filePath).replace(/\\/g, '/')
  for (const m of sopsYaml.matchAll(re)) {
    const pattern = m[2]
    if (!pattern) continue
    if (m[1] === 'path_regex') {
      try {
        if (new RegExp(pattern).test(relPath)) return true
      } catch {
        /* bad regex */
      }
    } else {
      const glob = pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '.')
      try {
        if (new RegExp(`^${glob}$`).test(relPath)) return true
      } catch {
        /* bad glob */
      }
    }
  }
  return false
}

// ============================================================================
// Decryption
// ============================================================================

type FileType = 'yaml' | 'json' | 'dotenv' | 'binary'

interface DecryptedFile {
  values: Map<string, string>
  keyLines: Map<string, number>
  plaintext: string
  type: FileType
  decryptedAt: number
  error?: string
}

const cache = new Map<string, DecryptedFile>()

function runSops(bin: string, args: string[], stdin?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { windowsHide: true })
    let stdout = ''
    let stderr = ''
    const timeout = setTimeout(() => {
      child.kill()
      reject(new Error('sops timed out after 10s'))
    }, 10_000)
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8')
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8')
    })
    child.on('error', (err) => {
      clearTimeout(timeout)
      reject(err)
    })
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
    return {
      values: new Map(),
      keyLines: new Map(),
      plaintext: '',
      type: 'yaml',
      decryptedAt: Date.now(),
      error: `File ${sizeKB.toFixed(0)} KB exceeds maxFileSizeKB=${maxKB}`,
    }
  }

  const type = inferInputType(doc)
  const useFile = doc.uri.scheme === 'file' && !doc.isDirty
  const args = [
    'decrypt',
    '--input-type',
    type,
    '--output-type',
    type,
    useFile ? doc.uri.fsPath : '/dev/stdin',
  ]

  try {
    const plaintext = await runSops(sopsBinary, args, useFile ? undefined : doc.getText())
    return parsePlaintext(plaintext, doc, type)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return {
      values: new Map(),
      keyLines: new Map(),
      plaintext: '',
      type,
      decryptedAt: Date.now(),
      error: msg.slice(0, 500),
    }
  }
}

function inferInputType(doc: vscode.TextDocument): FileType {
  const fname = path.basename(doc.fileName).toLowerCase()
  if (fname.endsWith('.json') || fname.endsWith('.json.enc')) return 'json'
  if (fname.includes('.env') || fname.endsWith('.dotenv') || fname.endsWith('.dotenv.enc')) return 'dotenv'
  if (
    fname.endsWith('.yaml') ||
    fname.endsWith('.yml') ||
    fname.endsWith('.yaml.enc') ||
    fname.endsWith('.yml.enc')
  )
    return 'yaml'
  if (fname.endsWith('.bin.enc') || fname.endsWith('.binary.enc') || fname.endsWith('.enc')) {
    const head = doc.getText(new vscode.Range(0, 0, Math.min(doc.lineCount, 20), 0))
    if (/^sops:|^\s*sops_version:/m.test(head)) return 'yaml'
    return 'binary'
  }
  return 'yaml'
}

function parsePlaintext(plaintext: string, doc: vscode.TextDocument, type: FileType): DecryptedFile {
  const values = new Map<string, string>()
  const keyLines = new Map<string, number>()

  if (type === 'binary') {
    values.set('__binary_blob__', plaintext)
    keyLines.set('__binary_blob__', 0)
    return { values, keyLines, plaintext, type, decryptedAt: Date.now() }
  }

  if (type === 'dotenv') {
    for (const line of plaintext.split(/\r?\n/)) {
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/)
      if (m) values.set(m[1]!, m[2]!)
    }
    for (let i = 0; i < doc.lineCount; i++) {
      const text = doc.lineAt(i).text
      const m = text.match(/^([A-Za-z_][A-Za-z0-9_]*)=/)
      if (m && values.has(m[1]!)) keyLines.set(m[1]!, i)
    }
  } else if (type === 'json') {
    try {
      const obj = JSON.parse(plaintext)
      flattenObject(obj, '', values)
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
      /* not parseable */
    }
  } else {
    const lines = plaintext.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? ''
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/)
      if (m && m[2]) values.set(m[1]!, m[2]!)
    }
    for (let i = 0; i < doc.lineCount; i++) {
      const text = doc.lineAt(i).text
      const m = text.match(/^([A-Za-z_][A-Za-z0-9_-]*):/)
      if (m && values.has(m[1]!)) keyLines.set(m[1]!, i)
    }
  }

  return { values, keyLines, plaintext, type, decryptedAt: Date.now() }
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

function truncate(s: string, max = 60): string {
  if (s.length <= max) return s
  return `${s.slice(0, max - 1)}…(${s.length} chars)`
}

function isPrintableUtf8(s: string): boolean {
  if (s.length === 0) return true
  let printable = 0
  for (const ch of s.slice(0, Math.min(s.length, 1000))) {
    const code = ch.charCodeAt(0)
    if (code >= 32 && code < 127) printable++
    else if (code === 9 || code === 10 || code === 13) printable++
  }
  return printable / Math.min(s.length, 1000) >= 0.9
}

function hexHead(s: string, n: number): string {
  const bytes = Buffer.from(s, 'binary').slice(0, n)
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ')
}

// ============================================================================
// CodeLens provider
// ============================================================================

class SopsCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>()
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event
  fire() {
    this._onDidChangeCodeLenses.fire()
  }

  async provideCodeLenses(doc: vscode.TextDocument): Promise<vscode.CodeLens[]> {
    const style = vscode.workspace.getConfiguration('sopsLens').get<string>('displayStyle', 'codelens')
    if (style !== 'codelens' && style !== 'all') return []
    if (!isEncryptedSopsFile(doc)) return []

    const decrypted = await ensureDecrypted(doc)
    if (decrypted.error) {
      return [
        new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
          title: `🔒 SOPS Lens — decrypt failed: ${decrypted.error.slice(0, 100)}`,
          command: '',
        }),
      ]
    }

    const lenses: vscode.CodeLens[] = []

    lenses.push(
      new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
        title: '✏️ Edit decrypted (virtual view)',
        tooltip: 'Open the decrypted plaintext in a virtual editor; save re-encrypts via sops',
        command: 'sopsLens.editVirtual',
        arguments: [doc.uri],
      }),
    )

    if (decrypted.type === 'binary') {
      const blob = decrypted.values.get('__binary_blob__') ?? ''
      const preview = isPrintableUtf8(blob)
        ? truncate(blob, 80)
        : `<binary ${blob.length} bytes — ${hexHead(blob, 16)}>`
      lenses.push(
        new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), {
          title: `🔓 ${preview}`,
          tooltip: 'Click to copy the full decrypted blob',
          command: 'sopsLens.copyValue',
          arguments: [blob, 'binary blob'],
        }),
      )
      return lenses
    }

    for (const [key, line] of decrypted.keyLines.entries()) {
      const value = decrypted.values.get(key) ?? ''
      lenses.push(
        new vscode.CodeLens(new vscode.Range(line, 0, line, 0), {
          title: `🔓 ${truncate(value)}`,
          tooltip: `Click to copy ${key}`,
          command: 'sopsLens.copyValue',
          arguments: [value, key],
        }),
      )
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
        md.appendCodeblock(`${key} = ${value}`, decrypted.type === 'json' ? 'json' : 'dotenv')
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
  if (decrypted.error || decrypted.type === 'binary') {
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
// Cache
// ============================================================================

async function ensureDecrypted(doc: vscode.TextDocument): Promise<DecryptedFile> {
  const key = doc.uri.toString()
  const cached = cache.get(key)
  if (cached) return cached
  const fresh = await decryptDocument(doc)
  cache.set(key, fresh)
  return fresh
}

function invalidate(uri: vscode.Uri): void {
  cache.delete(uri.toString())
}

// ============================================================================
// Edit-in-virtual-view
// ============================================================================

const SCHEME = 'sops-lens-edit'
const virtualToSource = new Map<string, vscode.Uri>()
const virtualContents = new Map<string, string>()

class SopsEditDocumentProvider implements vscode.TextDocumentContentProvider {
  private _onDidChange = new vscode.EventEmitter<vscode.Uri>()
  readonly onDidChange = this._onDidChange.event
  fire(uri: vscode.Uri) {
    this._onDidChange.fire(uri)
  }

  provideTextDocumentContent(uri: vscode.Uri): string {
    return virtualContents.get(uri.toString()) ?? ''
  }
}
const editDocProvider = new SopsEditDocumentProvider()

async function openVirtualEditView(sourceUri: vscode.Uri): Promise<void> {
  let sourceDoc: vscode.TextDocument
  try {
    sourceDoc = await vscode.workspace.openTextDocument(sourceUri)
  } catch (e) {
    vscode.window.showErrorMessage(`SOPS Lens: cannot open source file: ${e}`)
    return
  }
  const decrypted = await ensureDecrypted(sourceDoc)
  if (decrypted.error) {
    vscode.window.showErrorMessage(`SOPS Lens: cannot decrypt: ${decrypted.error}`)
    return
  }

  const baseName = path.basename(sourceUri.fsPath).replace(/\.enc$/i, '')
  const virtualPath = `/${baseName} (decrypted, unsaved)`
  const virtualUri = vscode.Uri.from({
    scheme: SCHEME,
    path: virtualPath,
    query: encodeURIComponent(sourceUri.toString()),
  })

  virtualContents.set(virtualUri.toString(), decrypted.plaintext)
  virtualToSource.set(virtualUri.toString(), sourceUri)
  editDocProvider.fire(virtualUri)

  const doc = await vscode.workspace.openTextDocument(virtualUri)
  const language =
    decrypted.type === 'json'
      ? 'json'
      : decrypted.type === 'dotenv'
        ? 'dotenv'
        : decrypted.type === 'binary'
          ? 'plaintext'
          : 'yaml'
  try {
    await vscode.languages.setTextDocumentLanguage(doc, language)
  } catch {
    /* harmless if language not registered */
  }
  await vscode.window.showTextDocument(doc, { preview: false })

  vscode.window.setStatusBarMessage(
    'SOPS Lens: edit then run "SOPS Lens: Save virtual (re-encrypt)" to write back',
    15_000,
  )
}

async function saveVirtualBackToSource(): Promise<void> {
  const ed = vscode.window.activeTextEditor
  if (!ed) {
    vscode.window.showWarningMessage('SOPS Lens: no active editor')
    return
  }
  if (ed.document.uri.scheme !== SCHEME) {
    vscode.window.showWarningMessage('SOPS Lens: active editor is not a virtual decrypted view')
    return
  }
  const sourceUri = virtualToSource.get(ed.document.uri.toString())
  if (!sourceUri) {
    vscode.window.showErrorMessage('SOPS Lens: lost mapping to source file')
    return
  }
  const newPlaintext = ed.document.getText()

  const cfg = vscode.workspace.getConfiguration('sopsLens')
  const sopsBinary = cfg.get<string>('sopsBinary', 'sops')
  const sourcePath = sourceUri.fsPath
  const fakeDocForType = await vscode.workspace.openTextDocument(sourceUri)
  const type = inferInputType(fakeDocForType)

  const args = ['encrypt', '--input-type', type, '--output-type', type, '/dev/stdin']
  try {
    const encrypted = await runSops(sopsBinary, args, newPlaintext)
    const tmp = `${sourcePath}.sops-lens-tmp`
    await fs.writeFile(tmp, encrypted, { encoding: 'utf8' })
    await fs.rename(tmp, sourcePath)

    invalidate(sourceUri)
    codeLensProvider.fire()
    for (const editor of vscode.window.visibleTextEditors) {
      if (editor.document.uri.toString() === sourceUri.toString()) {
        await vscode.commands.executeCommand('workbench.action.files.revert', sourceUri)
        await updateGhostTextDecorations(editor)
      }
    }
    vscode.window.setStatusBarMessage(`SOPS Lens: re-encrypted ${path.basename(sourcePath)}`, 5_000)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    vscode.window.showErrorMessage(`SOPS Lens: re-encrypt failed: ${msg}`)
  }
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
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, editDocProvider),

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
      ed.setDecorations(ghostTextDecoration, [])
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
        vscode.env.clipboard.readText().then((cur) => {
          if (cur === value) vscode.env.clipboard.writeText('')
        })
      }, 30_000)
    }),
    vscode.commands.registerCommand('sopsLens.editVirtual', async (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri
      if (!target) {
        vscode.window.showWarningMessage('SOPS Lens: no active file')
        return
      }
      await openVirtualEditView(target)
    }),
    vscode.commands.registerCommand('sopsLens.saveVirtual', saveVirtualBackToSource),

    vscode.workspace.onDidCloseTextDocument((doc) => {
      invalidate(doc.uri)
      if (doc.uri.scheme === SCHEME) {
        virtualContents.delete(doc.uri.toString())
        virtualToSource.delete(doc.uri.toString())
      }
    }),
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      invalidate(doc.uri)
      codeLensProvider.fire()
      const ed = vscode.window.visibleTextEditors.find((e) => e.document === doc)
      if (ed) await updateGhostTextDecorations(ed)
    }),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.uri.scheme === SCHEME) {
        virtualContents.set(e.document.uri.toString(), e.document.getText())
      }
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

  updateGhostTextDecorations(vscode.window.activeTextEditor)
}

export function deactivate(): void {
  cache.clear()
  virtualContents.clear()
  virtualToSource.clear()
}
