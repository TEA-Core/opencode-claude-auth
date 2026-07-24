import { accessSync, constants, lstatSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

export type CredentialGuardVerdict =
  | { safe: true }
  | {
      safe: false
      reason: "read_only_mode" | "symlink" | "not_writable" | "missing"
    }

/** Opt-in switch for deployments that manage credentials entirely out of band. */
const READ_ONLY_ENV = "CLAUDE_AUTH_READONLY_CREDENTIALS"

export function claudeCredentialsPath(): string {
  return join(homedir(), ".claude", ".credentials.json")
}

function readOnlyModeRequested(): boolean {
  const value = process.env[READ_ONLY_ENV]
  if (!value) return false
  const normalized = value.trim().toLowerCase()
  return normalized !== "" && normalized !== "0" && normalized !== "false"
}

/**
 * Decide whether it is safe for us to mutate the Claude credentials file.
 *
 * The file is often a symlink into a source we do not own and must not
 * replace: a container bind mount of the host's ~/.claude, a dotfiles repo, a
 * decrypted secret. Writing through such a link (or handing the path to
 * `claude`, which rewrites via temp+rename) destroys the link and leaves a
 * stale copy in its place, which then reads back as "expired credentials".
 *
 * We therefore only mutate a plain, writable, already-existing file.
 */
export function inspectClaudeCredentialsPath(
  path: string = claudeCredentialsPath(),
): CredentialGuardVerdict {
  if (readOnlyModeRequested()) {
    return { safe: false, reason: "read_only_mode" }
  }

  let stats: ReturnType<typeof lstatSync>
  try {
    stats = lstatSync(path)
  } catch {
    // Absent (or unreadable) -- never conjure a credentials file.
    return { safe: false, reason: "missing" }
  }

  if (stats.isSymbolicLink()) {
    return { safe: false, reason: "symlink" }
  }

  try {
    accessSync(path, constants.W_OK)
  } catch {
    return { safe: false, reason: "not_writable" }
  }

  return { safe: true }
}

/**
 * Guard against persisting a half-formed credential set. A failed refresh can
 * surface as empty tokens with a zeroed expiry; writing that back turns a
 * recoverable session into a permanently broken one.
 */
export function credentialsAreWritable(creds: {
  accessToken: string
  refreshToken: string
  expiresAt: number
}): boolean {
  return (
    creds.accessToken.trim().length > 0 &&
    creds.refreshToken.trim().length > 0 &&
    creds.expiresAt > 0
  )
}
