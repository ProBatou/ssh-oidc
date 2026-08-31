# ssh-oidc

Native PAM module for SSH authentication through an OpenID Connect Device Authorization Flow, with optional ntfy notifications.

## How it works

```text
OpenSSH
  -> PAM
  -> pam_ssh_oidc.so
       -> OIDC discovery
       -> Device Authorization
       -> optional ntfy notification
       -> token polling
       -> UserInfo
       -> user/group authorization
  -> SSH session
```

The module is written in C and has no Python or Go runtime dependency. For OpenSSH, the PAM module intentionally stays silent while authentication is pending: the ntfy notification is the out-of-band authentication prompt. Other PAM clients such as `pamtester` keep diagnostic messages.

## Runtime dependencies

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y libpam0g libcurl4t64 libjson-c5
```

Package names can differ on other distributions.

## Install a prebuilt release

Download `pam_ssh_oidc-linux-amd64.so` and `SHA256SUMS` from a versioned GitHub Release, verify the checksum, then install the module:

```bash
sha256sum -c SHA256SUMS
sudo install -d -m 0755 /usr/local/lib/security
sudo install -m 0755 pam_ssh_oidc-linux-amd64.so /usr/local/lib/security/pam_ssh_oidc.so
```

Nightly builds are development builds and are updated on every successful push to `main`.

## Configuration

Create `/etc/security/pam-ssh-oidc.conf`:

```ini
[ssh-oidc]
issuer=https://auth.example.com
client_id=YOUR_PUBLIC_CLIENT_ID
# client_secret=YOUR_CLIENT_SECRET
scope=openid profile email groups
timeout=180

allowed_linux_users=root
allow_users=
require_groups=ssh-admins

ntfy_url=https://ntfy.example.com
ntfy_topic=SSH_LOGIN
# ntfy_token=YOUR_NTFY_TOKEN
# ntfy_user=YOUR_NTFY_USER
# ntfy_password=YOUR_NTFY_PASSWORD
```

A public Device Flow client normally does not need `client_secret`.

Protect the configuration:

```bash
sudo chown root:root /etc/security/pam-ssh-oidc.conf
sudo chmod 600 /etc/security/pam-ssh-oidc.conf
```

### Authorization rules

- `allowed_linux_users`: Linux accounts allowed to use this PAM module.
- `allow_users`: comma-separated OIDC identities explicitly allowed.
- `require_groups`: comma-separated OIDC groups allowed to authenticate.
- If `require_groups` is empty, an OIDC identity matching the Linux username is accepted.

Matching is case-insensitive. UserInfo supports common identity claims such as `preferred_username`, `email`, `sub` and `name`. Groups can be strings or objects exposing common `name`, `display_name` or `id` fields.

## ntfy

ntfy is optional and only transports the Device Flow link/code. It does not approve the SSH connection.

Authentication options:

```ini
# Bearer token
ntfy_token=YOUR_NTFY_TOKEN

# Or HTTP Basic authentication
ntfy_user=YOUR_NTFY_USER
ntfy_password=YOUR_NTFY_PASSWORD
```

For SSH, configure ntfy when using the module: OpenSSH may buffer PAM informational messages until authentication completes, so the module intentionally does not print the Device Flow URL/code to an SSH terminal.

## PAM configuration

Keep a console or an existing privileged session open while changing PAM or sshd. A PAM configuration error can lock you out.

Example for `/etc/pam.d/sshd`, before `@include common-auth`:

```text
# root uses OIDC; other accounts continue through the normal PAM stack.
auth [success=1 default=ignore] pam_succeed_if.so quiet user != root
auth [success=done default=die] /usr/local/lib/security/pam_ssh_oidc.so
@include common-auth
```

See `config/pam.d-sshd-snippet`.

## OpenSSH configuration

OpenSSH uses the first value obtained for many global options. On distributions that ship an earlier file such as `10-template-security.conf` with `KbdInteractiveAuthentication no`, a later `90-oidc.conf` cannot override it. Put the global keyboard-interactive setting in an earlier file, for example `/etc/ssh/sshd_config.d/00-oidc.conf`:

```text
KbdInteractiveAuthentication yes
```

Then configure the protected account, for example:

```text
Match User root
    PermitRootLogin yes
    PasswordAuthentication no
    AuthenticationMethods keyboard-interactive:pam
```

Validate the effective configuration before restarting SSH:

```bash
sudo sshd -t
sudo sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -E 'usepam|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods'
```

Then restart/reload SSH according to the distribution.

## Test

```bash
ssh -tt \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=keyboard-interactive \
  -o PasswordAuthentication=no \
  root@SERVER_IP
```

Expected flow:

```text
SSH connection
  -> ntfy notification
  -> open OIDC provider
  -> approve with passkey / provider authentication
  -> module receives token
  -> UserInfo authorization
  -> SSH session opens
```

No additional Enter key is required after approval.

For PAM diagnostics outside OpenSSH:

```bash
pamtester ssh-oidc-test root authenticate
```

## Build from source

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev libcurl4-openssl-dev libjson-c-dev
make build
```

The result is `build/pam_ssh_oidc.so`.

Install locally:

```bash
sudo make install
```

## CI and releases

GitHub Actions builds on Ubuntu 24.04, verifies the exported PAM symbols, creates a SHA-256 checksum and uploads the build artifact.

```text
push main  -> build + rolling Nightly prerelease
tag v*     -> build + versioned GitHub Release
```

## Security

- Never commit real OIDC client secrets, ntfy tokens, passwords or private configuration.
- Keep `/etc/security/pam-ssh-oidc.conf` owned by root and mode `0600`.
- Use HTTPS for the OIDC provider and ntfy.
- Prefer authenticated/private ntfy topics because Device Flow notifications contain login metadata and an authentication URL/code.
- Keep an out-of-band console available while changing PAM/sshd.
- OIDC authentication proves identity; `allow_users` and `require_groups` decide whether that identity may open the requested Linux account.

## License

MIT.
