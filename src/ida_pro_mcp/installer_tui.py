def _ask(prompt: str) -> str | None:
    """Read one line; None on EOF/Ctrl+C or a 'q' answer (cancel)."""
    try:
        answer = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return None if answer.lower() == "q" else answer


def interactive_choose(items: list[str], title: str, default: int = 0) -> str | None:
    if not items:
        return None
    print(title)
    for i, name in enumerate(items, 1):
        print(f"  {i}. {name}")
    while True:
        answer = _ask(f"Choose 1-{len(items)} [{default + 1}], q to cancel: ")
        if answer is None:
            return None
        if not answer:
            return items[default]
        if answer.isdigit() and 1 <= int(answer) <= len(items):
            return items[int(answer) - 1]
        print("Invalid choice.")


def interactive_select(items: list[tuple[str, bool]], title: str) -> list[str] | None:
    if not items:
        return None
    selected = [checked for _, checked in items]
    while True:
        print(title)
        for i, (name, _) in enumerate(items, 1):
            print(f"  {i}. [{'x' if selected[i - 1] else ' '}] {name}")
        answer = _ask("Numbers to toggle (e.g. 1,3), a = all, enter = confirm, q = cancel: ")
        if answer is None:
            return None
        if not answer:
            return [name for (name, _), sel in zip(items, selected) if sel]
        if answer.lower() == "a":
            selected = [not all(selected)] * len(items)
            continue
        for part in answer.replace(",", " ").split():
            if part.isdigit() and 1 <= int(part) <= len(items):
                selected[int(part) - 1] = not selected[int(part) - 1]
            else:
                print(f"Ignored invalid entry: {part}")
