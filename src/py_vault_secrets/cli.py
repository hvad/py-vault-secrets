#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Authors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2025-10-03


import sys
import argparse
from getpass import getpass
from typing import List

# UI and Tools
from rich.table import Table
from rich.prompt import Prompt

# Application Logic
from vault import SecretManager, Secret
from config import console


# ----------------------------------------------------------------------
# Command Line Interface (CLI/rich)
# ----------------------------------------------------------------------

def display_secrets(keys: List[str]):
    """Displays the list of secret keys in a rich table."""
    if not keys:
        console.print(
            "[bold yellow]The vault is empty. Nothing to display.[/bold yellow]"
        )
        return

    table = Table(title="Stored Secrets", style="bold cyan")
    table.add_column("Index", style="dim", justify="right")
    table.add_column("Secret Key", style="bold white")

    for i, key in enumerate(keys):
        table.add_row(str(i + 1), key)

    console.print(table)


def prompt_for_new_secret(manager: SecretManager):
    """Guided dialogue to add a secret."""
    console.print("\n[bold cyan]--- ADD NEW SECRET ---[/bold cyan]")

    key = Prompt.ask("Key (Service/Account Name)").strip()
    if not key:
        console.print(
            "[bold red]Operation cancelled: Key is mandatory.[/bold red]")
        return

    # Check if key already exists before prompting for password
    if key in manager.secrets:
        console.print(
            f"[bold yellow] Key '{key}' already exists. Use 'modify'.[/bold yellow]"
        )
        return

    value = Prompt.ask("Value (Password/Token)", password=True)

    if not value:
        console.print(
            "[bold red]Operation cancelled: Value is mandatory.[/bold red]")
        return

    manager.add_secret(key, value)


def prompt_for_modification(manager: SecretManager):
    """Guided dialogue to modify a secret."""
    console.print("\n[bold cyan]--- MODIFY SECRET ---[/bold cyan]")

    key = Prompt.ask("Key to modify").strip()
    if not key:
        console.print(
            "[bold red]Operation cancelled: Key is mandatory for modification.[/bold red]"
        )
        return

    # Use the property for cleaner access
    if key not in manager.secrets:
        console.print(
            f"[bold red] Key '{
                key}' does not exist. Modification impossible.[/bold red]"
        )
        return

    new_value = Prompt.ask("New Value (Password/Token)", password=True)

    if not new_value:
        console.print(
            "[bold red]Operation cancelled: New value is mandatory.[/bold red]"
        )
        return

    manager.modify_secret(key, new_value)


def handle_interactive_mode(manager: SecretManager):
    """Runs the main interactive loop."""
    while True:
        console.print(
            "\n[bold yellow]------------------------------------------------[/bold yellow]"
        )
        console.print("[bold yellow]Interactive Secrets Manager[/bold yellow]")
        console.print(
            "[bold yellow]------------------------------------------------[/bold yellow]"
        )

        console.print("[bold white]Actions :[/bold white]")
        console.print(
            "  [green]A[/green]dd | [blue]M[/blue]odify | [magenta]D[/magenta]elete | [cyan]L[/cyan]ist | [yellow]V[/yellow]iew | [red]S[/red]earch | [bold red]Q[/bold red]uit"
        )

        choice = Prompt.ask(
            "Choose an action", choices=["a", "m", "d", "l", "v", "s", "q"], default="l"
        ).lower()

        if choice == "a":
            prompt_for_new_secret(manager)

        elif choice == "m":
            prompt_for_modification(manager)

        elif choice == "d":
            key_to_delete = Prompt.ask("Key to delete").strip()
            if not key_to_delete:
                console.print(
                    "[bold red]Operation cancelled: Key is mandatory for deletion.[/bold red]"
                )
                continue
            manager.delete_secret(key_to_delete)

        elif choice == "l":
            display_secrets(manager.list_keys())

        elif choice == "v":
            key_to_view = Prompt.ask(
                "Key whose [bold red]value[/bold red] you want to view"
            ).strip()
            if not key_to_view:
                console.print(
                    "[bold red]Operation cancelled: Key is mandatory to view value.[/bold red]"
                )
                continue

            value = manager.display_value(key_to_view)
            if value is None:
                console.print(f"[bold red] Key '{
                              key_to_view}' not found.[/bold red]")
            else:
                # Use print for clean output, avoiding rich formatting issues for copy/paste
                print(f"\nDecrypted value for '{key_to_view}': {value}")
                console.print(
                    "[bold green]Value displayed above (sensitive info)[/bold green]"
                )

        elif choice == "s":
            term = Prompt.ask("Search term").strip()
            if not term:
                console.print(
                    "[bold red]Operation cancelled: Search term cannot be empty.[/bold red]"
                )
                continue

            results = manager.search_secret(term)
            if results:
                console.print(f"Search results for '{term}':")
                display_secrets([s.key for s in results])
            else:
                console.print(
                    f"[bold yellow]No secrets found matching '{
                        term}'.[/bold yellow]"
                )

        elif choice == "q":
            console.print(
                "[bold green]Goodbye! The vault is locked.[/bold green]")
            break


def main():
    """Handles initialization and command execution."""

    parser = argparse.ArgumentParser(
        description="Secure Secret Manager (ANSSI - Rich CLI Interface)",
        epilog="Run without arguments for interactive mode or use --help for direct commands.",
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available direct commands")

    subparsers.add_parser("list", help="List all secret keys.")
    subparsers.add_parser(
        "interactive",
        help="Launch the interactive interface (default if no arguments).",
    )

    parser_add = subparsers.add_parser("add", help="Add a secret (directly).")
    # Added required=True for clarity in direct commands
    parser_add.add_argument("key", type=str, help="Key of the secret.")
    parser_add.add_argument("value", type=str, help="Value of the secret.")

    parser_del = subparsers.add_parser(
        "delete", help="Delete a secret (directly).")
    parser_del.add_argument("key", type=str, help="Key of the secret to delete.")

    parser_get = subparsers.add_parser(
        "view", help="Display the decrypted value of a secret."
    )
    parser_get.add_argument("key", type=str, help="Key of the secret to view.")

    parser_search = subparsers.add_parser(
        "search", help="Search secrets by key.")
    parser_search.add_argument("term", type=str, help="Search term (partial match).")

    args = parser.parse_args()

    # --- Initial Authentication ---
    console.print("\n[bold underline] Vault Authentication:[/bold underline]")
    master_pwd = getpass("Enter your Master Password: ")

    try:
        manager = SecretManager(master_pwd)
    except ValueError as e:
        # Handles the error raised by authentication failure
        console.print(f"[bold red] Authentication Error: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red] Initialization Error: {e}[/bold red]")
        sys.exit(1)


    # --- Execution Mode ---

    command = args.command

    # If no command is provided, default to interactive mode
    if command is None:
        command = "interactive"

    if command != "interactive":
        if command == "list":
            display_secrets(manager.list_keys())

        elif command == "add":
            manager.add_secret(args.key, args.value)

        elif command == "delete":
            manager.delete_secret(args.key)

        elif command == "search":
            results = manager.search_secret(args.term)
            if results:
                console.print(f"Search results for '{args.term}':")
                display_secrets([s.key for s in results])
            else:
                console.print(
                    f"[bold yellow]No secrets found matching '{
                        args.term}'.[/bold yellow]"
                )

        elif command == "view":
            value = manager.display_value(args.key)
            if value is None:
                console.print(f"[bold red] Key '{
                              args.key}' not found.[/bold red]")
            else:
                # Use print for clean output, avoiding rich formatting for easy copy/paste
                print(f"\nDecrypted value for '{args.key}': {value}")
                console.print(
                    "[bold green]Value displayed above (sensitive info)[/bold green]"
                )
        return

    # Interactive mode
    handle_interactive_mode(manager)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Catch unexpected errors gracefully
        console.print(
            f"\n[bold red]An unexpected fatal error occurred: {e}[/bold red]", file=sys.stderr
        )
        sys.exit(1)
