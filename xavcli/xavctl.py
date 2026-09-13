import typer
import rich
from rich.console import Console
import json
import socket
import uuid

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

    # Send request.
    req_uuid = str(uuid.uuid4())
    s.send(json.dumps({
        "jsonrpc": "2.0",
        "method": "xavcore::app::proactive_protection_module_api::Api::status",
        "params": [],
        "id": req_uuid,
    }).encode())

    # Parse response.
    resp = s.recv(4096)
    resp = json.loads(resp.decode())

    if "error" in resp:
        console.print(f"Error: {resp['error']['code']}: {resp['error']['message']}")
        return
        
    # Print status.
    result = resp["result"]
    console.print(f"Status: [green]{result['status']}[/green]")
    console.print()
    console.print(f"Active Process: {result['active_proc_count']}")
    console.print(f"Suspicious Process: [yellow]{result['suspicious_proc_count']}[/yellow]")
    console.print(f"Malicious Process: [red]{result['malicious_proc_count']}[/red]")
    console.print()
    console.print(f"Total Event: {result['event_count']}")
    console.print(f"Event Violates Rules: [yellow]{result['violate_rules_event_count']}[/yellow]")

if __name__ == "__main__":
    main_app()
