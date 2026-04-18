export interface StoredAuth {
  access: string
  refresh: string
  expires: number
  accountId?: string
}

const KEYCHAIN_SERVICE = "claude-codex-proxy"
const KEYCHAIN_ACCOUNT = "auth"
const SECRET_TOOL_LABEL = "claude-codex-proxy auth"
const SECRET_TOOL_ATTRIBUTES = ["service", KEYCHAIN_SERVICE, "account", KEYCHAIN_ACCOUNT] as const

export async function loadAuth(): Promise<StoredAuth | undefined> {
  const raw = await loadStoredValue()
  if (!raw) return undefined
  return JSON.parse(raw) as StoredAuth
}

export async function saveAuth(auth: StoredAuth): Promise<void> {
  await saveStoredValue(JSON.stringify(auth))
}

export async function clearAuth(): Promise<void> {
  await clearStoredValue()
}

export function authPath(): string {
  if (process.platform === "darwin") return "macOS Keychain"
  if (process.platform === "linux") return "Linux Secret Service"
  return "unsupported auth storage"
}

async function loadStoredValue(): Promise<string | undefined> {
  if (process.platform === "darwin") {
    return readKeychain().catch((err: Error & { code?: number }) => {
      if (err.code === 44) return undefined
      throw err
    })
  }
  if (process.platform === "linux") {
    return readSecret().catch((err: Error & { code?: number }) => {
      if (err.code === 1) return undefined
      throw err
    })
  }
  throw new Error("Auth storage is only supported on macOS and Linux")
}

async function saveStoredValue(value: string): Promise<void> {
  if (process.platform === "darwin") {
    await runCommand("security", [
      "add-generic-password",
      "-U",
      "-a",
      KEYCHAIN_ACCOUNT,
      "-s",
      KEYCHAIN_SERVICE,
      "-w",
      value,
    ])
    return
  }
  if (process.platform === "linux") {
    await runCommand("secret-tool", ["store", "--label", SECRET_TOOL_LABEL, ...SECRET_TOOL_ATTRIBUTES], value)
    return
  }
  throw new Error("Auth storage is only supported on macOS and Linux")
}

async function clearStoredValue(): Promise<void> {
  if (process.platform === "darwin") {
    await runCommand("security", ["delete-generic-password", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE]).catch(
      (err: Error & { code?: number }) => {
        if (err.code !== 44) throw err
      },
    )
    return
  }
  if (process.platform === "linux") {
    await runCommand("secret-tool", ["clear", ...SECRET_TOOL_ATTRIBUTES]).catch((err: Error & { code?: number }) => {
      if (err.code !== 1) throw err
    })
    return
  }
  throw new Error("Auth storage is only supported on macOS and Linux")
}

async function readKeychain(): Promise<string> {
  const { stdout } = await runCommand("security", ["find-generic-password", "-w", "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE])
  return stdout.trim()
}

async function readSecret(): Promise<string> {
  const { stdout } = await runCommand("secret-tool", ["lookup", ...SECRET_TOOL_ATTRIBUTES])
  return stdout.trim()
}

async function runCommand(command: string, args: string[], stdin?: string): Promise<{ stdout: string; stderr: string }> {
  const proc = Bun.spawn([command, ...args], {
    stdin: stdin === undefined ? "ignore" : "pipe",
    stdout: "pipe",
    stderr: "pipe",
  })
  if (stdin !== undefined && proc.stdin) {
    proc.stdin.write(stdin)
    proc.stdin.end()
  }
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  if (exitCode !== 0) {
    const message = stderr.trim() || stdout.trim() || `${command} exited with ${exitCode}`
    const err = new Error(message) as Error & { code?: number }
    err.code = exitCode
    throw err
  }
  return { stdout, stderr }
}
