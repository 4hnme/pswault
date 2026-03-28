# pswault

A simple password manager written in Odin.

## Features

- AES-CTR encryption for vault data.
- Simple CLI interface for managing records.
- Support for inserting, querying, and deleting records.

## Usage

```bash
pswault <action> <vault_path> <key> [args...]
```

### Actions

- `create`: Initialize a new vault.
  ```bash
  pswault create vault.bin mypassword
  ```
- `insert`: Add records to the vault.
  ```bash
  pswault insert vault.bin mypassword "site_name" "username" "password"
  ```
- `delete`: Removes records from the vault.
  ```bash
  pswault delete vault.bin mypassword "site_name"
  ```
- `query`: Retrieve records from the vault.
  ```bash
  pswault query vault.bin mypassword "site_name" # prints "username,password"
  ```
> `insert`, `delete` and `query` actions can accept multiple parameters.
