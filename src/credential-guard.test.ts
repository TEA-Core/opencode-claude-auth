import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  claudeCredentialsPath,
  credentialsAreWritable,
  inspectClaudeCredentialsPath,
} from "./credential-guard.ts"

async function withHome<T>(fn: (home: string) => T): Promise<T> {
  const originalHome = process.env.HOME
  const home = await mkdtemp(join(tmpdir(), "opencode-claude-auth-guard-"))
  process.env.HOME = home
  try {
    return fn(home)
  } finally {
    if (originalHome === undefined) delete process.env.HOME
    else process.env.HOME = originalHome
  }
}

function seedCredentials(home: string): string {
  const dir = join(home, ".claude")
  mkdirSync(dir, { recursive: true })
  const path = join(dir, ".credentials.json")
  writeFileSync(
    path,
    JSON.stringify({
      claudeAiOauth: {
        accessToken: "at",
        refreshToken: "rt",
        expiresAt: Date.now() + 3_600_000,
      },
    }),
  )
  return path
}

describe("inspectClaudeCredentialsPath", () => {
  it("treats an ordinary writable credentials file as safe to mutate", async () => {
    await withHome((home) => {
      seedCredentials(home)
      assert.deepEqual(inspectClaudeCredentialsPath(), { safe: true })
    })
  })

  // The credentials file is frequently a symlink into a read-only, externally
  // managed source (a container bind mount of the host's ~/.claude, a dotfiles
  // repo, an age/sops-decrypted path). Mutating it -- directly, or indirectly by
  // handing the path to `claude`, which rewrites via temp+rename -- destroys the
  // link and substitutes a stale copy.
  it("refuses a symlinked credentials file", async () => {
    await withHome((home) => {
      const dir = join(home, ".claude")
      mkdirSync(dir, { recursive: true })
      const real = join(home, "real-credentials.json")
      writeFileSync(real, "{}")
      symlinkSync(real, join(dir, ".credentials.json"))

      assert.deepEqual(inspectClaudeCredentialsPath(), {
        safe: false,
        reason: "symlink",
      })
    })
  })

  it("refuses a read-only credentials file", async () => {
    await withHome((home) => {
      const path = seedCredentials(home)
      chmodSync(path, 0o400)
      try {
        assert.deepEqual(inspectClaudeCredentialsPath(), {
          safe: false,
          reason: "not_writable",
        })
      } finally {
        chmodSync(path, 0o600)
      }
    })
  })

  it("refuses a missing credentials file rather than creating one", async () => {
    await withHome(() => {
      assert.deepEqual(inspectClaudeCredentialsPath(), {
        safe: false,
        reason: "missing",
      })
    })
  })

  it("honours an explicit read-only opt-in", async () => {
    const original = process.env.CLAUDE_AUTH_READONLY_CREDENTIALS
    process.env.CLAUDE_AUTH_READONLY_CREDENTIALS = "1"
    try {
      await withHome((home) => {
        seedCredentials(home)
        assert.deepEqual(inspectClaudeCredentialsPath(), {
          safe: false,
          reason: "read_only_mode",
        })
      })
    } finally {
      if (original === undefined)
        delete process.env.CLAUDE_AUTH_READONLY_CREDENTIALS
      else process.env.CLAUDE_AUTH_READONLY_CREDENTIALS = original
    }
  })

  it("resolves the credentials path from HOME", async () => {
    await withHome((home) => {
      assert.equal(
        claudeCredentialsPath(),
        join(home, ".claude", ".credentials.json"),
      )
    })
  })
})

describe("credentialsAreWritable", () => {
  it("rejects blank or unset tokens so a failed refresh cannot blank the file", () => {
    const future = Date.now() + 3_600_000
    assert.equal(
      credentialsAreWritable({
        accessToken: "",
        refreshToken: "rt",
        expiresAt: future,
      }),
      false,
    )
    assert.equal(
      credentialsAreWritable({
        accessToken: "at",
        refreshToken: "",
        expiresAt: future,
      }),
      false,
    )
    assert.equal(
      credentialsAreWritable({
        accessToken: "at",
        refreshToken: "rt",
        expiresAt: 0,
      }),
      false,
    )
    assert.equal(
      credentialsAreWritable({
        accessToken: "at",
        refreshToken: "rt",
        expiresAt: future,
      }),
      true,
    )
  })
})
