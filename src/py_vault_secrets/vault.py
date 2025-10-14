#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Authors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2025-10-03


import base64
import json
import secrets
from typing import Dict, List, Optional
from pathlib import Path

# Security and Crypto
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration and Console
from config import console, ITERATIONS, FILE_NAME, SALT_FILE, KEY_LENGTH


# --- Secret Classes and Manager ---

class Secret:
    """Represents a key-value entry in the manager."""

    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value


class SecretManager:
    """Manages storage, encryption, and CRUD operations for secrets."""

    def __init__(self, master_password: str):
        self._master_password_bytes = master_password.encode()
        self._secrets: Dict[str, Secret] = {}
        self._fernet: Optional[Fernet] = None

        # Initialization logic moved here to ensure config is loaded
        self._initialize_vault()

    def _get_salt(self) -> bytes:
        """Loads the existing salt or creates a new one."""
        salt_path = Path(SALT_FILE)
        if salt_path.exists():
            return salt_path.read_bytes()
        else:
            # Create a new secure salt
            salt = secrets.token_bytes(KEY_LENGTH)
            salt_path.write_bytes(salt)
            return salt

    def _derive_key(self, salt: bytes) -> bytes:
        """Derives the encryption key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
        )
        # The key must be base64 url-safe encoded for Fernet
        return base64.urlsafe_b64encode(kdf.derive(self._master_password_bytes))

    def _initialize_vault(self):
        """Initializes the Fernet key and attempts to load secrets."""
        salt = self._get_salt()
        fernet_key = self._derive_key(salt)
        self._fernet = Fernet(fernet_key)

        self._load_secrets()

    # --- Data Persistence (I/O) ---

    def _encrypt(self, data: str) -> str:
        """Encrypts a string."""
        if not self._fernet:
            raise RuntimeError("Vault not initialized for encryption.")
        return self._fernet.encrypt(data.encode()).decode()

    def _decrypt(self, token: str) -> str:
        """Decrypts a string."""
        if not self._fernet:
            raise RuntimeError("Vault not initialized for decryption.")
        return self._fernet.decrypt(token.encode()).decode()

    def _load_secrets(self):
        """Loads and decrypts secrets from the file."""
        vault_path = Path(FILE_NAME)

        if not vault_path.exists():
            return

        try:
            with vault_path.open("r") as f:
                # Optimized: Read the whole file once
                encrypted_data = json.load(f)
        except json.JSONDecodeError:
            console.print(
                "[bold yellow] Secrets file is corrupt or empty. Creating a new vault.[/bold yellow]"
            )
            return
        except Exception as e:
            console.print(f"[bold red] File read error: {e}[/bold red]")
            return

        self._secrets.clear()
        try:
            for encrypted_key, encrypted_value in encrypted_data.items():
                key = self._decrypt(encrypted_key)
                value = self._decrypt(encrypted_value)
                self._secrets[key] = Secret(key, value)
        except Exception:
            # This is the critical authentication check point
            raise ValueError(
                "Invalid Master Password or Corrupt Data."
            )

    def _save_secrets(self):
        """Encrypts and saves all secrets."""
        encrypted_data: Dict[str, str] = {
            self._encrypt(secret.key): self._encrypt(secret.value)
            for secret in self._secrets.values()
        }

        # Ensure the file path exists (especially useful if running from another directory)
        Path(FILE_NAME).parent.mkdir(parents=True, exist_ok=True)

        with Path(FILE_NAME).open("w") as f:
            json.dump(encrypted_data, f, indent=4)

    # --- CRUD Operations (Concise and Pythonic) ---

    def add_secret(self, key: str, value: str):
        """Adds a new secret."""
        if key in self._secrets:
            console.print(
                f"[bold yellow] Key '{
                    key}' already exists. Use 'modify'.[/bold yellow]"
            )
            return

        self._secrets[key] = Secret(key, value)
        self._save_secrets()
        console.print(f"[bold green] Secret '{key}' added.[/bold green]")

    def modify_secret(self, key: str, new_value: str):
        """Modifies the value of an existing secret."""
        if key not in self._secrets:
            console.print(f"[bold red] Key '{
                          key}' does not exist.[/bold red]")
            return

        self._secrets[key].value = new_value
        self._save_secrets()
        console.print(f"[bold blue] Secret '{key}' modified.[/bold blue]")

    def delete_secret(self, key: str):
        """Deletes a secret by its key."""
        if key in self._secrets:
            del self._secrets[key]
            self._save_secrets()
            console.print(f"[bold magenta]🗑️ Secret '{
                          key}' deleted.[/bold magenta]")
        else:
            console.print(f"[bold red] Key '{
                          key}' does not exist.[/bold red]")

    def search_secret(self, term: str) -> List[Secret]:
        """Searches for secrets by key (partial match)."""
        lower_term = term.lower()
        return [
            secret for key, secret in self._secrets.items() if lower_term in key.lower()
        ]

    def list_keys(self) -> List[str]:
        """Lists all secret keys."""
        return sorted(self._secrets.keys())

    def display_value(self, key: str) -> Optional[str]:
        """Returns the decrypted value of a specific secret or None."""
        secret = self._secrets.get(key)
        return secret.value if secret else None

    # Expose secrets dictionary for CLI checks (optional, but convenient for the UI layer)
    @property
    def secrets(self) -> Dict[str, Secret]:
        return self._secrets
