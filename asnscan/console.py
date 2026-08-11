"""One rich Console for the whole program, plus the message prefixes.

Markers are ASCII on purpose: a Windows console in a legacy code page
will happily render "[+]" and choke on a box-drawing glyph.
"""

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.theme import Theme

THEME = Theme({
    "info": "cyan",
    "good": "green",
    "warn": "yellow",
    "bad": "bold red",
    "muted": "dim",
    "head": "bold white on rgb(31,56,100)",
})

console = Console(theme=THEME, highlight=False, soft_wrap=False)


def info(msg):
    console.print(f"[info][+][/info] {msg}")


def good(msg):
    console.print(f"[good][*][/good] {msg}")


def warn(msg):
    console.print(f"[warn][!][/warn] {msg}")


def bad(msg):
    console.print(f"[bad][x][/bad] {msg}")


def rule(title=""):
    console.rule(f"[bold]{title}" if title else "", style="muted")


def progress_bar(known_total=True):
    """
    The scan progress display.

    IPv4 knows how many addresses it must visit, so it gets a bar and an
    ETA. The IPv6 walk does not - its total is discovered as it prunes -
    so it gets a spinner and live counters instead.
    """

    columns = [
        SpinnerColumn(style="info"),
        TextColumn("[bold]{task.description}"),
    ]

    if known_total:
        columns += [
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            MofNCompleteColumn(),
        ]

    columns += [
        TextColumn("[muted]|[/muted] {task.fields[extra]}"),
        TimeElapsedColumn(),
    ]

    if known_total:
        columns.append(TimeRemainingColumn(compact=True))

    return Progress(*columns, console=console, refresh_per_second=6,
                    expand=True)
