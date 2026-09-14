import typer
import rich
from rich.console import Console
from rich.box import SIMPLE_HEAD
from rich.table import Table
from datetime import datetime
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

# Placeholder for nullable fields.
UNKNOWN = "<unknown>"

def display(value):
    """Render a nullable JSON value."""
    return UNKNOWN if value is None else str(value)

def display_time(epoch_millis):
    """Render a millisecond epoch timestamp in local time."""
    if epoch_millis is None:
        return UNKNOWN
    return datetime.fromtimestamp(epoch_millis / 1000).strftime("%Y-%m-%d %H:%M:%S")

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

@proactive_app.command("ps")
def proactive_ps():
    """List the processes monitored by proactive protection"""
    result = call("processes")
    if result is None:
        console.print("Failed to list processes")
        return

    if not result:
        console.print("No processes monitored yet")
        return

    table = Table(box=SIMPLE_HEAD)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("Start Time", no_wrap=True)
    table.add_column("PPID", justify="right", no_wrap=True)
    table.add_column("Path", no_wrap=True, overflow="ellipsis", max_width=32)
    table.add_column("Command Line", no_wrap=True, overflow="ellipsis",
                     max_width=40)
    table.add_column("Events", justify="right", no_wrap=True)
    table.add_column("Violations", justify="right", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Level", no_wrap=True)

    for process in result:
        table.add_row(
            str(process["pid"]),
            display_time(process["start_time"]),
            display(process["ppid"]),
            display(process["exe_path"]),
            display(process["cmdline"]),
            str(process["event_count"]),
            str(process["violated_event_count"]),
            str(round(process["severity_score"])),
            process["severity_level"],
        )

    # Piped output has no known width, and Rich would then squeeze this table
    # into its 80 column default. Render at a fixed width so no column is lost.
    out = console if console.is_terminal else Console(width=200, highlight=False)
    out.print(table)

if __name__ == "__main__":
    main_app()
