from rich.console import Console


class ConsoleLogger:
    """Small console logger used by the CLI and scan pipeline."""

    def __init__(self) -> None:
        self._console = Console()

    def info(self, message: str) -> None:
        self._console.print(f"[cyan][INFO][/cyan] {message}")

    def success(self, message: str) -> None:
        self._console.print(f"[green][OK][/green] {message}")

    def warning(self, message: str) -> None:
        self._console.print(f"[yellow][WARN][/yellow] {message}")

    def error(self, message: str) -> None:
        self._console.print(f"[red][ERROR][/red] {message}")
