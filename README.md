# Wrapped Goose

A bubblewrap-based sandbox wrapper for [Goose](https://github.com/block/goose) AI agent.

## What This Does

This script runs Goose inside a sandboxed environment using [bubblewrap](https://github.com/containers/bubblewrap), providing:

- **Filesystem isolation**: Read-only access to your system, Read-write access only to the project directory (and some cache files for npm, python, and uv, which can be removed if needed).
- **Environment filtering**: Only whitelisted environment variables are passed through
- **Network isolation** (optional): Complete network namespace isolation when needed
- **Flexible path binding**: Bind any directories your tools need via `EXTRA_PATH`

## Requirements

- [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`)
- [Goose](https://github.com/block/goose)

## Installation

### Option 1: Local Install (Recommended)

Install in `~/.local/bin` so it automatically wraps all Goose commands:

```bash
# Create directory if needed
mkdir -p ~/.local/bin

# Copy the script
cp goose ~/.local/bin/
chmod +x ~/.local/bin/goose

# Ensure ~/.local/bin is in your PATH
# Add to ~/.bashrc or ~/.zshrc if not already there:
export PATH="$HOME/.local/bin:$PATH"
```

**How it works**: The wrapper script must appear in your PATH **before** the real `goose` binary. When you type `goose`, this script runs first, sets up the sandbox, then calls the real Goose.

### Option 2: System-wide Install (Not Recommended)

```bash
chmod +x goose
sudo cp goose /usr/local/bin/
```

**Note**: Make sure `/usr/local/bin` comes before the original Goose location in your PATH.

## Usage

### Basic Usage

```bash
# Run Goose normally (sandboxed)
goose

# Run with a specific command
goose run --recipe my-recipe.yaml
```

### Environment Variables

#### `EXTRA_PATH`

Colon-separated list of additional paths to bind as read-only (like `PATH`).

```bash
# Single path
EXTRA_PATH=/home/user/my-tools goose run

# Multiple paths
EXTRA_PATH=/home/user/.venv:/home/user/tools:/opt/custom goose run
```

#### `GOOSE_ISOLATE_NETWORK`

Enable complete network isolation (unshare all namespaces).

```bash
GOOSE_ISOLATE_NETWORK=1 goose run
```

### Combined Example

```bash
# Full isolation with custom tools
GOOSE_ISOLATE_NETWORK=1 EXTRA_PATH=/home/user/project/.venv:/home/user/bin goose run --recipe my-recipe.yaml
```

## Bound Directories

The sandbox automatically binds these directories:

| Path                                     | Access     | Purpose                        |
| ---------------------------------------- | ---------- | ------------------------------ |
| `$PROJECT_DIR`                           | Read-write | Your current working directory |
| `~/.config/goose`                        | Read-write | Goose configuration            |
| `~/.local/share/goose`                   | Read-write | Goose data                     |
| `~/.local/state/goose`                   | Read-write | Goose state                    |
| `~/.npm/`                                | Read-write | NPM cache                      |
| `/usr`, `/bin`, `/lib`, `/lib64`, `/etc` | Read-only  | System directories             |

### Custom Path Binding

Use `EXTRA_PATH` to bind any additional directories your tools need (e.g., UV cache, Python interpreters, virtual environments):

```bash
# Bind UV cache and Python interpreters
EXTRA_PATH="$HOME/.cache/uv:$HOME/.local/share/uv/python" goose run

# Bind a virtual environment
EXTRA_PATH=/path/to/.venv goose run
```

## Whitelisted Environment Variables

The following environment variables are passed through to the sandbox:

- **API Keys**: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOSE_API_KEY`, `GEMINI_API_KEY`, `COHERE_API_KEY`
- **SSH/Git**: `SSH_AUTH_SOCK`, `SSH_AGENT_LAUNCHER`, `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`
- **User/Session**: `USER`, `LOGNAME`, `HOME`, `SHELL`, `TERM`, `COLORTERM`, `LANG`, `LC_ALL`
- **XDG**: `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR`
- **Editor**: `EDITOR`, `VISUAL`
- **Development**: `GOPATH`, `GOROOT`, `NODE_PATH`, `PYTHONPATH`, `JAVA_HOME`

## TODO

- Add support for macOS

## Troubleshooting

### "bad interpreter: No such file or directory"

Your virtual environment's Python is outside the sandbox. Add the Python installation directory to `EXTRA_PATH`:

```bash
EXTRA_PATH=/path/to/.venv:/path/to/python/installation goose run
```

### MCP servers fail to start

MCP servers need access to their interpreters and dependencies. Use `EXTRA_PATH` to bind the necessary directories:

```bash
EXTRA_PATH=/path/to/mcp-server/.venv goose run
```

### Network-related features don't work

By default, network is shared. If you enable `GOOSE_ISOLATE_NETWORK`, Goose won't have network access.
