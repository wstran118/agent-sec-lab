"""Which commands would a POSIX shell run for this line? Nothing is executed.

The lab never runs model-built command lines for real. This parser lets tests prove that a string-built
command line spawns attacker-chosen commands (injection) while an argv-list call cannot.
"""
import shlex

OPS = set(";&|\n")


def _split_subst(line: str) -> tuple[str, list[str]]:
    """Pull out $(...) and `...` spans that the shell would expand (not inside single quotes)."""
    out, subs, i, in_single, in_double = [], [], 0, False, False
    while i < len(line):
        c = line[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "\n" and not in_single and not in_double:
            c = ";"  # an unquoted newline separates commands
        if not in_single and line.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(line) and depth:
                depth += (line[j] == "(") - (line[j] == ")")
                j += 1
            subs.append(line[i + 2 : j - 1])
            out.append(" SUBST ")
            i = j
            continue
        if not in_single and c == "`":
            j = line.find("`", i + 1)
            j = len(line) if j < 0 else j
            subs.append(line[i + 1 : j])
            out.append(" SUBST ")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), subs


def simulate(line: str) -> list[list[str]]:
    """Return argv lists of every simple command the shell would run, in order. Redirections stay as tokens."""
    top, subs = _split_subst(line)
    commands: list[list[str]] = []
    for s in subs:
        commands += simulate(s)
    lex = shlex.shlex(top, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    current: list[str] = []
    try:
        tokens = list(lex)
    except ValueError:
        tokens = top.split()
    for tok in tokens:
        if tok and set(tok) <= OPS:
            if current:
                commands.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        commands.append(current)
    return commands
