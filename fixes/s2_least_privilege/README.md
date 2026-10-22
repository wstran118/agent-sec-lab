# S2 fix: least privilege

The baseline tools trust whatever the model asks for. Three controls, each enforced in code:

| Flaw | Control |
|---|---|
| `read_file`/`write_file` accept `..`, absolute paths, symlinks | `confine_paths`: `Path.resolve()` first (collapses `..`, follows symlinks), then require the result is inside the workspace |
| Writes anywhere in the workspace, including `.env` | `write_dirs`: writes only under `workspace/out` |
| `run_shell` takes any string | `shell_allowlist`: `ls`/`wc`/`date` only, no `; & \| $ \` < >`, path arguments confined like files |
| Every task gets every tool | `allowed_tools` (see `PROFILES`): schemas for other tools are not shown to the model, and calls to them are refused anyway |

Notes and limits:
- Resolve-then-open has a TOCTOU window if something else can swap a symlink between the check and the open; the read-only container filesystem is the backstop. The check opens the *resolved* path, which narrows it.
- The workspace still contains `.env`; confinement does not stop reading it. Keeping secrets out of the workspace and out of context is S6.
- Real shell execution should use an argv list with no shell (`subprocess.run([...])`) in a throwaway container; the lab keeps `run_shell` a stub.
