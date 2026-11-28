# The `hiccup` CLI

`hiccup --help` and `hiccup <command> --help` describe every command. This page covers what applies to all of them.

## Global flags

| Flag | Meaning |
|------|---------|
| `--json` | Print results as JSON, for scripts. |
| `--instance NAME` | The instance to control (default: the only running one), or the name of the one to start. Also `HICCUP_INSTANCE`. |
| `--project FILE` | The project file an instance started by this command (`serve`, `proxy start --foreground`) records history in. |
| `--data-dir DIR` | Where Hiccup keeps its data: the CA and `config.json`. Also `HICCUP_DATA_DIR`. |
| `--runtime-dir DIR` | The registry of running instances. Also `HICCUP_RUNTIME_DIR`. |
| `-v`, `-vv` | More logs (debug, trace). `RUST_LOG` overrides them. |
| `-q` | Errors only. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | The command failed: no instance is running, the instance refused the request (e.g. no held message with that ID), a file cannot be read or written. The message on standard error says why. |
| `2` | The command line is wrong: an unknown command or flag, a missing argument, an invalid value (e.g. `--timeout -1`, an unknown `config` key). Nothing was done. |

Errors are always written to standard error; results go to standard output (as JSON with `--json`).

## Saved defaults (`hiccup config`)

`hiccup config set KEY VALUE` saves a default in `config.json` in the data directory; a flag given on the command line always wins. `hiccup config get` lists the keys:

| Key | Default for | Example |
|-----|-------------|---------|
| `project` | `--project` | `hiccup config set project ~/work/acme.hiccup` |
| `proxy.listen` | `proxy start --listen` (comma-separated) | `hiccup config set proxy.listen 127.0.0.1:8081` |
| `proxy.verify-upstream` | `proxy start --no-verify-upstream` (default `true`: certificates are verified) | `hiccup config set proxy.verify-upstream false` |

`hiccup config unset KEY` goes back to the built-in default.

## Shell completions

```sh
hiccup completions bash > ~/.local/share/bash-completion/completions/hiccup
hiccup completions zsh  > "${fpath[1]}/_hiccup"
hiccup completions fish > ~/.config/fish/completions/hiccup.fish
hiccup completions powershell >> $PROFILE
```

## Man pages

`hiccup man --output DIR` writes one page per command (`hiccup.1`, `hiccup-proxy-start.1`, …):

```sh
hiccup man --output ~/.local/share/man/man1 && man hiccup-history-list
```
