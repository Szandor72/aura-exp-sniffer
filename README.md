# Aura-Exp-Sniffer

> A simple security research tool to access undocumented Aura APIs within Salesforce Experience Cloud context. Works only with Aura based communities

![image](https://github.com/Szandor72/aura-exp-sniffer/assets/16804218/af2a8c88-a90a-47db-baf8-2c25655ffe61)


## Project Details

This is a [Poetry](https://python-poetry.org/) based python project. [Typer](https://typer.tiangolo.com/) is used for CLI.

## Installation

```bash
poetry install
aura-exp-sniffer --help

```

## Usage

### Commands and option

`--url` option is required needs to used for every command.

```bash
 Usage: aura-exp-sniffer [OPTIONS] COMMAND [ARGS]...

 Aura Sniffer: A simple security research tool to access undocumented Aura APIs

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --url                 -u      TEXT  Experience Cloud URL, e.g. https://company.portal.com/s [required]            │
│    --token               -t      TEXT  JSON with Aura Token and SID (session id) to access Aura APIs                 │
│    --install-completion                Install completion for the current shell.                                     │
│    --show-completion                   Show completion for the current shell, to copy it or customize the            │
│                                        installation.                                                                 │
│    --help                              Show this message and exit.                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ apex-methods        Get all Apex methods exposed in custom components                                                │
│ call-apex           Call an Apex method with params. Method parameters need to be made available within a JSON file  │
│ custom-components   Get all exposed custom component names                                                           │
│ dump                Dump accessible records to files. Retrieve 10 records per sObject by default.                    │
│ feed-items          Get feed items by record Id                                                                      │
│ profile-menu        Get the profile menu                                                                             │
│ record              Get record by record Id                                                                          │
│ records             Get records by sObject API Name                                                                  │
│ routes              Get all available Aura routes                                                                    │
│ search              Search for records by term and sObject API Name. At least one additional fields is required.     │
│ sobjects            Will print most accessible Standard and Custom sObjects respectively.                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Aura Token

A valid `--token` option looks like this

```json
{
  "token": "<aura_token>",
  "sid": "<session_id>"
}
```

### Example

```bash
aura-exp-sniffer --url https://company.portal.com/s --token '{"token": "<aura_token>", "sid": "<session_id>"}' sobjects
```
