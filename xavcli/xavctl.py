import typer
import rich
from rich.console import Console
import json
import socket

# Connect.
SOCKET_PATH = "\0xavcore_proactive_protection_module_socket"
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(SOCKET_PATH)

# Typers.
main_app = typer.Typer()
on_access_app = typer.Typer()
proactive_app = typer.Typer()
main_app.add_typer(on_access_app, name="onaccess", help="On-Access Scanner Module")
main_app.add_typer(proactive_app, name="proactive", help="Proactive Protection Module")

# Console.
console = Console(highlight=False)

@proactive_app.command("start")
def proactive_start():
    """Start proactive protection"""
    pass

@proactive_app.command("stop")
def proactive_stop():
    """Stop proactive protection"""
    pass

@proactive_app.command("status")
def status():
    """Check proactive protection status"""
    s.send(json.dumps({"method": "status"}).encode())
    resp = s.recv(4096)
    resp = json.loads(resp.decode())
    console.print(resp)
    # console.print(f"Status: [green]Running[/green]")
    # console.print()
    # console.print(f"Active Process: 1203")
    # console.print(f"Suspicious Process: [yellow]12[/yellow]")
    # console.print(f"Malicious Process: [red]1[/red]")
    # console.print()
    # console.print(f"Total Event: 302834")
    # console.print(f"Event Violates Rules: [yellow]129[/yellow]")

if __name__ == "__main__":
    main_app()
