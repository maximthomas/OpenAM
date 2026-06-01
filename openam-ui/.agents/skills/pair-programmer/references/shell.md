# Shell / Bash Reference — Pair Programmer

## Safety Defaults — Always Start Scripts With

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

- `set -e` — exit immediately on error (without this, failures are silently ignored)
- `set -u` — treat unset variables as errors (catches typos in variable names)
- `set -o pipefail` — pipeline fails if any command fails (not just the last)
- `IFS=$'\n\t'` — prevents word splitting on spaces in filenames

---

## Quoting — The #1 Source of Shell Bugs

**Always quote variable expansions:**
```bash
# Bug: breaks on filenames with spaces
rm $file

# Correct
rm "$file"

# Bug: word-splits the glob
files=$*
for f in $files; do ...

# Correct
for f in "$@"; do ...   # "$@" preserves argument boundaries
```

**When to use which quotes:**
- `"$var"` — double quotes: expands variables, prevents word splitting
- `'literal'` — single quotes: no expansion at all
- `$(command)` — command substitution (prefer over backticks)
- `$((expr))` — arithmetic expansion

---

## Variables and Substitution

**Default values:**
```bash
name="${1:-default}"          # use default if $1 is unset or empty
name="${NAME:?NAME is required}"  # error and exit if unset/empty
```

**String manipulation:**
```bash
file="path/to/script.sh"
echo "${file##*/}"    # basename: script.sh
echo "${file%/*}"     # dirname:  path/to
echo "${file%.sh}"    # strip suffix: path/to/script
echo "${file^^}"      # uppercase (bash 4+)
echo "${#file}"       # length
```

**Arrays:**
```bash
items=("a" "b" "c")
echo "${items[0]}"         # first element
echo "${items[@]}"         # all elements (properly quoted)
echo "${#items[@]}"        # length
for item in "${items[@]}"; do  # correct iteration
    echo "$item"
done
```

---

## Error Handling

**Check return codes explicitly when `set -e` would be too aggressive:**
```bash
if ! command_that_may_fail; then
    echo "Failed, handling gracefully"
fi

# Or capture exit code
command_that_may_fail || exit_code=$?
```

**Trap for cleanup on exit:**
```bash
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT   # runs on any exit, including errors

# Multiple signals
trap 'cleanup; exit 1' INT TERM ERR
```

**Meaningful error messages:**
```bash
die() {
    echo "ERROR: $*" >&2   # stderr, not stdout
    exit 1
}

[[ -f "$config" ]] || die "Config file not found: $config"
```

---

## Common Patterns

**Portable shebang:**
```bash
#!/usr/bin/env bash  # finds bash on PATH — more portable than /bin/bash
```

**Read file line by line:**
```bash
while IFS= read -r line; do
    echo "$line"
done < "$file"
# IFS= prevents stripping leading/trailing whitespace
# -r prevents backslash interpretation
```

**Process substitution:**
```bash
diff <(sort file1) <(sort file2)  # compare sorted outputs without temp files
```

**Heredoc:**
```bash
cat <<'EOF'
This text is $literal (single-quote heredoc)
EOF

cat <<EOF
This text uses $variables (regular heredoc)
EOF
```

**Check if a command exists:**
```bash
if command -v docker &>/dev/null; then
    docker ps
fi
```

---

## Security in Shell Scripts

**Never pass user input to shell directly:**
```bash
# DANGEROUS: command injection
eval "ls $user_input"
bash -c "echo $user_input"

# Safe: use arrays for commands
cmd=("ls" "--" "$user_input")
"${cmd[@]}"
```

**Secure temp files:**
```bash
tmpfile=$(mktemp)           # secure, unique filename
tmpdir=$(mktemp -d)         # secure temp directory
trap 'rm -f "$tmpfile"' EXIT
```

**Avoid `sudo` in scripts where possible; document when it's required.**

**Validate inputs early:**
```bash
[[ "$1" =~ ^[0-9]+$ ]] || die "Expected numeric argument, got: $1"
```

---

## Portability Notes

| Feature | bash | sh (POSIX) |
|---------|------|------------|
| Arrays | ✓ | ✗ |
| `[[` | ✓ | ✗ (use `[`) |
| `$(( ))` arithmetic | ✓ | ✓ |
| `local` in functions | ✓ | ✓ (most) |
| `&>>` append redirect | ✓ | ✗ |
| String manipulation `${var^^}` | ✓ bash 4 | ✗ |

If targeting POSIX sh (e.g., Alpine, BusyBox): use `#!/bin/sh`, no arrays, no `[[`.

---

## Debugging

```bash
set -x          # print each command before executing (very useful)
set +x          # turn off

bash -n script.sh   # syntax check without running
bash -x script.sh   # trace execution
shellcheck script.sh  # static analysis — run this on all scripts
```

**`shellcheck` is the pair programmer's best friend for shell scripts. Always recommend it.**
