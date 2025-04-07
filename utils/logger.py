from rich.console import Console
from rich.text import Text

console = Console()

def info(msg):
    console.print(f"[bold blue][INFO][/bold blue] {msg}")

def success(msg):
    console.print(f"[bold green][SUCCESS][/bold green] {msg}")

def warning(msg):
    console.print(f"[bold yellow][WARNING][/bold yellow] {msg}")

def error(msg):
    console.print(f"[bold red][ERROR][/bold red] {msg}")
