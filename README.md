# (Draft) Python Vault Secrets CLI

**Warning** Not for production use.
This code/package is for testing, development, or educational purposes only and 
should not be deployed in a live production environment.

## Overview

This script provides a secure command-line interface for managing secrets
using the `rich` library for enhanced user experience.

It allows you to add, modify, delete, list, view, and search for secrets securely.

## Installation

Ensure you have Python installed on your system.
Then, install the required dependencies using pip:

```bash
pip install py_vault_secrets
```

## Usage

### Direct Commands

You can run specific commands directly from the command line without entering
the interactive mode.

Here are some examples:

#### List All Secret Keys

```bash
python cli.py list
```

#### Add a Secret

```bash
python cli.py add my_service my_password
```

#### Delete a Secret

```bash
python cli.py delete my_service
```

#### View a Secret

```bash
python cli.py view my_service
```

#### Search Secrets

```bash
python cli.py search service
```

### Interactive Mode

For more advanced interactions, you can enter the interactive mode by running
the script without any arguments:

```bash
python cli.py
```

In the interactive mode, you will be presented with a menu where you can choose
actions such as adding, modifying, deleting, listing, viewing,
and searching for secrets.

## Features

- **Interactive Mode**: A user-friendly interface for managing secrets.
- **Direct Commands**: Quick access to common operations without entering the
interactive mode.
- **Rich Formatting**: Enhanced visual representation of secret lists and messages.
- **Authentication**: Secure authentication using a master password.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the Apache License.

