#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Authors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2025-10-03
#   Updated: 2025-10-14 (Added Label functionality)


from pathlib import Path
from typing import Dict, Final

from rich.console import Console

# Initialize the rich console
console = Console()

# --- Configuration Variables (Defaults) ---
# Use Final for constants for better type hinting
ENV_VARS: Dict[str, any] = {
    "ITERATIONS": 480000,
    "FILE_NAME": "vault.json",
    "SALT_FILE": "salt.bin",
    "KEY_LENGTH": 32,
}

# Assign the default values as Final for immediate use/typing
ITERATIONS: Final[int] = ENV_VARS["ITERATIONS"]
FILE_NAME: Final[str] = ENV_VARS["FILE_NAME"]
SALT_FILE: Final[str] = ENV_VARS["SALT_FILE"]
KEY_LENGTH: Final[int] = ENV_VARS["KEY_LENGTH"]


def load_env_constants():
    """Loads configuration constants from a local .env file and updates ENV_VARS."""
    global ITERATIONS, FILE_NAME, SALT_FILE, KEY_LENGTH

    env_path = Path(".env")
    if not env_path.exists():
        console.print(
            "[bold yellow] .env file not found. Using default internal constants.[/bold yellow]"
        )
        return

    try:
        with env_path.open("r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Split only on the first '='
                    try:
                        key, value = line.split("=", 1)
                    except ValueError:
                        continue # Skip malformed lines

                    key = key.strip()
                    # Clean up quotes from the value
                    value = value.strip().strip('"').strip("'")

                    # Convert to appropriate type (integer)
                    if key in ["ITERATIONS", "KEY_LENGTH"]:
                        try:
                            ENV_VARS[key] = int(value)
                        except ValueError:
                            console.print(
                                f"[bold red] Invalid integer value for {key} in .env. Using default.[/bold red]"
                            )
                    elif key in ["FILE_NAME", "SALT_FILE"]:
                        ENV_VARS[key] = value

        # Update global constants with potentially loaded values
        ITERATIONS = ENV_VARS["ITERATIONS"]
        FILE_NAME = ENV_VARS["FILE_NAME"]
        SALT_FILE = ENV_VARS["SALT_FILE"]
        KEY_LENGTH = ENV_VARS["KEY_LENGTH"]

    except Exception as e:
        console.print(
            f"[bold red] Error loading .env file: {e}. Using default internal constants.[/bold red]"
        )

# Load constants upon import
load_env_constants()
