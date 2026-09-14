import typer
import rich
from rich.console import Console
import json
import socket
import uuid

# Typers.
main_app = typer.Typer()
on_access_app = typer.Typer()
proactive_app = typer.Typer()
main_app.add_typer(on_access_app, name="onaccess", help="On-Access Scanner Module")
main_app.add_typer(proactive_app, name="proactive", help="Proactive Protection Module")

# Console.
console = Console(highlight=False)

# Proactive protection module API.
API = "xavcore::app::proactive_protection_module_api::Api"

# Socket connection.
def connect():
    SOCKET_PATH = "\0xavcore_proactive_protection_module_socket"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.connect(SOCKET_PATH)
    return s

def call(method: str):
    """Send one JSON-RPC request and return its result, or None on failure."""
    try:
        s = connect()
        try:
            s.send(json.dumps({
                "jsonrpc": "2.0",
                "method": f"{API}::{method}",
                "params": [],
                "id": str(uuid.uuid4()),
            }).encode())
            resp = json.loads(s.recv(4096).decode())
        finally:
            s.close()
    except socket.error as e:
        console.print(f"Socket Error: [red]{e}[/red]")
        return None

    if "error" in resp:
        console.print(f"Error: {resp['error']['code']}: {resp['error']['message']}")
        return None
    return resp["result"]

@proactive_app.command("start")
def proactive_start():
    """Start proactive protection"""
    result = call("start")
    if result is None:
        console.print(
            f"Failed to start proactive protection"
        )

@proactive_app.command("stop")
def proactive_stop():
    """Stop proactive protection"""
    result = call("stop")
    if result is None:
        console.print(
            f"Failed to stop proactive protection"
        )

@proactive_app.command("status")
def status():
    """Check proactive protection status"""
    result = call("status")
    if result is None:
        console.print(
            f"Failed to get proactive protection status"
        )
        return

    if "error" in result:
        console.print(
            f"Failed to get proactive protection status: {result["error"]["message"]} ({result["error"]["code"]})"
        )
        return

    if result["status"] == "Running":
        console.print("Status: [green]Running[/green]")
    else:
        console.print("Status: [red][bold]Stopped[/bold][/red]")
    console.print()
    console.print(f"Suspicious Process Count: [yellow]{result['suspicious_proc_count']}[/yellow]")
    console.print(f"Malicious Process Count: [red]{result['malicious_proc_count']}[/red]")
    console.print()
    console.print(f"Total Event: {result['event_count']}")
    console.print(f"Event Violates Rules: [yellow]{result['violate_rules_event_count']}[/yellow]")

if __name__ == "__main__":
    main_app()
