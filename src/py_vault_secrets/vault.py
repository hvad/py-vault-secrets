#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Authors:
#       David Hannequin <david.hannequin@gmail.com>
#   Date : 2025-10-03
#   Updated: 2025-10-14 (Added Label functionality)


import base64
import json
import secrets
from typing import Dict, List, Optional, Set
from pathlib import Path

# Security and Crypto
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration and Console
from config import console, ITERATIONS, FILE_NAME, SALT_FILE, KEY_LENGTH


# --- Secret Classes and Manager ---

class Secret:
    """Represents a key-value entry in the manager, now including labels."""

    def __init__(self, key: str, value: str, labels: Optional[List[str]] = None):
        self.key = key
        self.value = value
        # Store as a Set for uniqueness and faster lookups
        self.labels: Set[str] = set(labels) if labels else set()


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
            # Handle the updated data structure (encrypted content is now a JSON string containing value and labels)
            for encrypted_key, encrypted_content in encrypted_data.items():
                
                # 1. Decrypt the key and content
                decrypted_key = self._decrypt(encrypted_key)
                decrypted_content_str = self._decrypt(encrypted_content)
                
                # 2. Parse the content JSON
                secret_content = json.loads(decrypted_content_str)
                
                # 3. Extract key, value, and labels
                value = secret_content["value"]
                # Use .get for labels to support backward compatibility if needed
                labels = secret_content.get("labels", []) 
                
                self._secrets[decrypted_key] = Secret(decrypted_key, value, labels)
        except Exception:
            # This is the critical authentication check point
            raise ValueError(
                "Invalid Master Password or Corrupt Data."
            )

    def _save_secrets(self):
        """Encrypts and saves all secrets."""
        encrypted_data: Dict[str, str] = {}
        for secret in self._secrets.values():
            
            # 1. Create the content dictionary (must be JSON serializable)
            content_to_store = {
                "value": secret.value,
                # Convert the set of labels to a list for JSON serialization
                "labels": sorted(list(secret.labels)) 
            }
            
            # 2. Serialize and Encrypt the content
            encrypted_content = self._encrypt(json.dumps(content_to_store))
            
            # 3. Encrypt the key and add to the dictionary
            encrypted_data[self._encrypt(secret.key)] = encrypted_content

        # Ensure the file path exists (especially useful if running from another directory)
        Path(FILE_NAME).parent.mkdir(parents=True, exist_ok=True)

        with Path(FILE_NAME).open("w") as f:
            json.dump(encrypted_data, f, indent=4)

    # --- CRUD Operations (Concise and Pythonic) ---

    def add_secret(self, key: str, value: str, labels: Optional[str] = None):
        """Adds a new secret."""
        if key in self._secrets:
            console.print(
                f"[bold yellow] Key '{
                    key}' already exists. Use 'modify'.[/bold yellow]"
            )
            return
            
        # Parse the comma-separated labels string into a list/set of clean, lower-cased labels
        parsed_labels = [l.strip().lower() for l in (labels or "").split(',') if l.strip()]

        new_secret = Secret(key, value, parsed_labels)
        self._secrets[key] = new_secret
        self._save_secrets()
        console.print(f"[bold green] Secret '{key}' added with labels: {', '.join(new_secret.labels)}.[/bold green]")


    def modify_secret(self, key: str, new_value: Optional[str] = None, new_labels: Optional[str] = None):
        """Modifies the value and/or labels of an existing secret."""
        if key not in self._secrets:
            console.print(f"[bold red] Key '{key}' does not exist.[/bold red]")
            return

        secret = self._secrets[key]
        modified = False

        if new_value is not None:
            secret.value = new_value
            modified = True
            console.print(f"[bold blue] Value of '{key}' modified.[/bold blue]")

        if new_labels is not None:
            # Replace existing labels with new ones
            parsed_labels = {l.strip().lower() for l in new_labels.split(',') if l.strip()}
            secret.labels = parsed_labels
            modified = True
            console.print(f"[bold blue] Labels of '{key}' modified to: {', '.join(secret.labels)}.[/bold blue]")

        if modified:
            self._save_secrets()
        else:
            console.print("[bold yellow] Nothing to modify.[/bold yellow]")


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

    def search_secret(self, term: str, search_labels: bool = True) -> List[Secret]:
        """Searches for secrets by key (partial match) and/or by label."""
        lower_term = term.lower()
        results: List[Secret] = []
        for key, secret in self._secrets.items():
            # 1. Search by Key
            key_match = lower_term in key.lower()

            # 2. Search by Label (if enabled)
            label_match = False
            if search_labels:
                # Check if the term is present in any of the labels
                label_match = any(lower_term in label for label in secret.labels)

            if key_match or label_match:
                results.append(secret)
                
        return results

    def list_secrets_with_labels(self) -> List[Dict[str, any]]:
        """Lists all secret keys and their labels."""
        data = [
            # Convert set to list for easy consumption/display
            {"key": secret.key, "labels": sorted(list(secret.labels))}
            for secret in self._secrets.values()
        ]
        # Sort by key
        return sorted(data, key=lambda x: x['key'])

    def list_keys(self) -> List[str]:
        """Lists all secret keys (only keys)."""
        return sorted(self._secrets.keys())

    def display_value(self, key: str) -> Optional[str]:
        """Returns the decrypted value of a specific secret or None."""
        secret = self._secrets.get(key)
        return secret.value if secret else None

    # Expose secrets dictionary for CLI checks (optional, but convenient for the UI layer)
    @property
    def secrets(self) -> Dict[str, Secret]:
        return self._secrets
