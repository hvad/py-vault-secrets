#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Authors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2025-10-03
#   Updated: 2025-10-14 (Added Label functionality)
#   Updated: 2025-10-15 (Added 'import' command for CSV)


import sys
import argparse
import csv  # New import for CSV handling
from getpass import getpass
from typing import List, Dict, Any

# UI and Tools
from rich.table import Table
from rich.prompt import Prompt

# Application Logic
from vault import SecretManager, Secret
from config import console


# ----------------------------------------------------------------------
# Command Line Interface (CLI/rich)
# ----------------------------------------------------------------------


def display_secrets(secrets_data: List[Dict[str, Any]]):
    """Displays the list of secret keys and their labels in a rich table."""
    if not secrets_data:
        console.print(
            "[bold yellow]The vault is empty. Nothing to display.[/bold yellow]"
        )
        return

    table = Table(title="Stored Secrets", style="bold cyan")
    table.add_column("Index", style="dim", justify="right")
    table.add_column("Secret Key", style="bold white")
    # New column for labels
    table.add_column("Labels", style="italic yellow")

    for i, data in enumerate(secrets_data):
        labels_str = ", ".join(data["labels"])
        table.add_row(
            str(i +
                1), data["key"], labels_str if labels_str else "[dim]None[/dim]"
        )

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
            f"[bold yellow] Key '{
                key}' already exists. Use 'modify'.[/bold yellow]"
        )
        return

    value = Prompt.ask("Value (Password/Token)", password=True)
    if not value:
        console.print(
            "[bold red]Operation cancelled: Value is mandatory.[/bold red]")
        return

    # Prompt for labels (optional)
    labels = Prompt.ask(
        "Labels (comma-separated, e.g., 'work, social') [optional]"
    ).strip()

    manager.add_secret(key, value, labels)


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
                key
            }' does not exist. Modification impossible.[/bold red]"
        )
        return

    # Get current labels for display
    current_labels = ", ".join(manager.secrets[key].labels)

    # Prompt for new value (optional)
    new_value_input = Prompt.ask(
        "New Value (Password/Token) [leave blank to keep current]", password=True
    )
    new_value = new_value_input if new_value_input else None

    # Prompt for new labels (optional)
    # The user enters the full list of labels they want the secret to have
    new_labels_input = Prompt.ask(
        f"New Labels (comma-separated) [current: {
            current_labels
        } | leave blank to keep current]"
    ).strip()
    new_labels = new_labels_input if new_labels_input else None

    # modify_secret handles the case where both are None
    manager.modify_secret(key, new_value, new_labels)


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
        # Updated description for L and S
        console.print(
            "  [green]A[/green]dd | [blue]M[/blue]odify | [magenta]D[/magenta]elete | [cyan]L[/cyan]ist (Keys & Labels) | [yellow]V[/yellow]iew (Value) | [red]S[/red]earch (Key/Label) | [bold red]Q[/bold red]uit"
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
            # Display keys AND labels
            display_secrets(manager.list_secrets_with_labels())

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
            term = Prompt.ask("Search term (Key or Label)").strip()
            if not term:
                console.print(
                    "[bold red]Operation cancelled: Search term cannot be empty.[/bold red]"
                )
                continue

            # Search in both key and labels
            results = manager.search_secret(term, search_labels=True)
            if results:
                console.print(f"Search results for '{term}':")
                # Format results for display
                results_data = [
                    {"key": s.key, "labels": sorted(list(s.labels))} for s in results
                ]
                display_secrets(results_data)
            else:
                console.print(
                    f"[bold yellow]No secrets found matching '{
                        term}'.[/bold yellow]"
                )

        elif choice == "q":
            console.print(
                "[bold green]Goodbye! The vault is locked.[/bold green]")
            break


# NEW FUNCTION TO HANDLE CSV IMPORT
def handle_import(manager: SecretManager, csv_path: str):
    """Reads secrets from a CSV file and imports them."""
    try:
        with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
            # Use DictReader to treat the first row as headers
            reader = csv.DictReader(f, fieldnames=["key", "value", "labels"])

            # Skip the header row if present, assuming 'key' is the first field
            # A more robust check might be needed, but for simplicity, we'll skip the first row
            # if we assume the user provides the file path directly (not via stdin).
            # We'll skip the first row only if it contains 'key', 'value', or 'labels' to handle headers.
            secrets_data = list(reader)

            if secrets_data and secrets_data[0].get("key", "").lower() == "key":
                secrets_data.pop(0)  # Remove header row

            # Clean up and ensure keys/values are strings, labels default to empty string
            import_data = []
            for row in secrets_data:
                # Use .get to safely retrieve values, defaulting to empty string
                key = row.get("key", "").strip()
                value = row.get("value", "").strip()
                labels = row.get("labels", "").strip()

                if key and value:  # Only import if key and value are present
                    import_data.append(
                        {"key": key, "value": value, "labels": labels})

            if not import_data:
                console.print(
                    "[bold yellow]CSV file contains no valid data rows (requires 'key' and 'value').[/bold yellow]"
                )
                return

            manager.import_secrets_from_data(import_data)

    except FileNotFoundError:
        console.print(f"[bold red]Error: CSV file not found at '{
                      csv_path}'[/bold red]")
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while reading or importing the CSV file: {
                e
            }[/bold red]"
        )


def main():
    """Handles initialization and command execution."""

    parser = argparse.ArgumentParser(
        description="Secure Secret Manager (ANSSI - Rich CLI Interface)",
        epilog="Run without arguments for interactive mode or use --help for direct commands.",
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available direct commands")

    # Updated description
    subparsers.add_parser(
        "list", help="List all secret keys and their labels.")
    subparsers.add_parser(
        "interactive",
        help="Launch the interactive interface (default if no arguments).",
    )

    parser_add = subparsers.add_parser("add", help="Add a secret (directly).")
    # Added required=True for clarity in direct commands
    parser_add.add_argument("key", type=str, help="Key of the secret.")
    parser_add.add_argument("value", type=str, help="Value of the secret.")
    # New argument for labels
    parser_add.add_argument(
        "--labels",
        type=str,
        default="",
        help="Comma-separated labels for the secret (e.g., 'work, social').",
    )

    # NEW PARSER FOR IMPORT COMMAND
    parser_import = subparsers.add_parser(
        "import", help="Import secrets from a CSV file (format: key,value,labels)."
    )
    parser_import.add_argument(
        "csv_path",
        type=str,
        help="Path to the CSV file containing secrets (columns: key, value, labels).",
    )

    parser_del = subparsers.add_parser(
        "delete", help="Delete a secret (directly).")
    parser_del.add_argument(
        "key", type=str, help="Key of the secret to delete.")

    parser_get = subparsers.add_parser(
        "view", help="Display the decrypted value of a secret."
    )
    parser_get.add_argument("key", type=str, help="Key of the secret to view.")

    parser_search = subparsers.add_parser(
        "search", help="Search secrets by key or label."
    )  # Updated description
    parser_search.add_argument(
        "term", type=str, help="Search term (partial match in key or label)."
    )

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
            # List secrets with labels
            display_secrets(manager.list_secrets_with_labels())

        elif command == "add":
            # Pass labels argument
            manager.add_secret(args.key, args.value, args.labels)

        elif command == "import":
            # Handle the new import command
            handle_import(manager, args.csv_path)

        elif command == "delete":
            manager.delete_secret(args.key)

        elif command == "search":
            # Search in both key and labels
            results = manager.search_secret(args.term, search_labels=True)
            if results:
                console.print(f"Search results for '{args.term}':")
                # Format results for display
                results_data = [
                    {"key": s.key, "labels": sorted(list(s.labels))} for s in results
                ]
                display_secrets(results_data)
            else:
                console.print(
                    f"[bold yellow]No secrets found matching '{
                        args.term
                    }'.[/bold yellow]"
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
            f"\n[bold red]An unexpected fatal error occurred: {e}[/bold red]",
            file=sys.stderr,
        )
        sys.exit(1)
