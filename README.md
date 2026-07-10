# Ethical Hacker Toolkit

Local security tooling, built and used for authorized auditing/analysis of contracts and
binaries you own or are engaged to test.

- **`Tools/auditkit`** — Solidity static analysis, fuzz-test scaffolding, exploit PoC scaffolding.
- **`Tools/binarykit`** — binary static analysis (hash/entropy/strings/symbols) and sandboxed
  dynamic analysis (isolated execution with syscall/network logging).

Both are Bun/TypeScript CLIs, run directly via `bun run src/cli.ts <command>`.

## Prerequisites

| Tool | Requires |
|---|---|
| both | [Bun](https://bun.sh) >= 1.1.0 |
| auditkit | [Foundry](https://getfoundry.sh) (`forge`) — needed for `fuzz`/`exploit` scaffolds and for running Slither in-place |
| auditkit (optional) | Python 3 + `slither-analyzer` + `solc-select`, for cross-checking findings against Slither |
| binarykit `disasm` | `objdump` |
| binarykit `sandbox` | `bubblewrap` (`bwrap`) + `strace` — **Linux only**; on Windows, run from inside WSL |

### Install Bun

```bash
npm install -g bun          # or: curl -fsSL https://bun.sh/install | bash
```

### Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup                   # installs forge, cast, anvil, chisel
```

If `foundryup` can't detect your shell, add `~/.foundry/bin` to `PATH` yourself.

## auditkit

```bash
cd Tools/auditkit
bun install

bun run src/cli.ts static contracts/YourContract.sol      # run detectors
bun run src/cli.ts fuzz contracts/YourContract.sol         # generate a Foundry fuzz scaffold
bun run src/cli.ts exploit -f <findingId> -o test/exploits # generate an exploit PoC scaffold
bun run src/cli.ts report findings/<file>.json             # render a findings JSON as Markdown
bun run src/cli.ts recon -a <address> -c <chain>           # fetch verified source from a block explorer
```

`contracts/` and `findings/` are gitignored — they're your working scratch space, not tool source.

### Cross-checking with Slither (optional)

Slither auto-detects `foundry.toml` and shells out to `forge`, so make sure Foundry is
installed first (above). Isolate it in its own venv rather than your system Python:

```bash
cd Tools/auditkit
python -m venv .venv-slither
./.venv-slither/Scripts/python.exe -m pip install slither-analyzer solc-select   # Scripts/ -> bin/ on macOS/Linux

./.venv-slither/Scripts/solc-select.exe install 0.8.20   # match your contract's pragma
./.venv-slither/Scripts/solc-select.exe use 0.8.20

# add .venv-slither/Scripts (or bin) to PATH first, so `solc` resolves for slither/forge:
export PATH="$PWD/.venv-slither/Scripts:$PATH"
slither contracts/YourContract.sol --json findings/slither-YourContract.json
```

## binarykit

```bash
cd Tools/binarykit
bun install

bun run src/cli.ts inspect samples/target                  # hashes, entropy, strings, symbols
bun run src/cli.ts disasm samples/target -s main            # disassemble one symbol
bun run src/cli.ts report reports/<file>.json               # render an inspect JSON as Markdown
```

`samples/` and `reports/` are gitignored.

### Sandbox (dynamic analysis)

Requires `bubblewrap` + `strace`, which are Linux-only. **On Windows, run this from inside
WSL** — it will not work in PowerShell/cmd/git-bash directly.

One-time WSL setup:

```bash
wsl --install -d Ubuntu
wsl -d Ubuntu -u root -- bash -c "apt-get update && apt-get install -y bubblewrap strace unzip curl && curl -fsSL https://bun.sh/install | bash"
```

Then, from inside WSL (project files are visible under `/mnt/c/...`):

```bash
cd "/mnt/c/path/to/Tools/binarykit"
bun install
bun run src/cli.ts sandbox samples/target \
  --args <arg1> <arg2> \
  --timeout 15 \
  --md reports/target-behavior.md
```

Network is isolated by default (DNS and outbound connections both fail); pass
`--allow-network` to permit them. The tool refuses to run anything unsandboxed if `bwrap`
isn't installed.

```bash
bun run src/cli.ts sandbox samples/target --args <args...> --allow-network --md reports/target-behavior.md
```

## Scope

These tools are for analyzing contracts/binaries you own or are authorized to test.
`binarykit` is observability-only — no patching, keygen, or protection-bypass generation.
`auditkit`'s exploit PoCs fork chain state locally via Anvil; point them only at
contracts you're authorized to test.
