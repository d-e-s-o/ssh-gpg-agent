[![pipeline](https://gitlab.com/d-e-s-o/ssh-gpg-agent/badges/master/pipeline.svg)](https://gitlab.com/d-e-s-o/ssh-gpg-agent/commits/master)
[![crates.io](https://img.shields.io/crates/v/ssh-gpg-agent.svg)](https://crates.io/crates/ssh-gpg-agent)
[![rustc](https://img.shields.io/badge/rustc-1.32+-blue.svg)](https://blog.rust-lang.org/2019/01/17/Rust-1.32.0.html)

ssh-gpg-agent
=============

- [Changelog](CHANGELOG.md)

**ssh-gpg-agent** is an alternative SSH agent implementation that
transparently supports PGP encrypted private SSH keys, instead of
relying on password protection. Unlike SSH agents as provided by GnuPG
or OpenSSH, there is no need to "add" them to the agent -- key discovery
is automatic in a given directory.


### The Context

For a given user, there can be merit in having a single SSH key per host
instead of a shared one for all hosts a given user wants to connect to.
Benefits include but are not necessary limited to:
- Compromise of a key only compromises a single service
- Simplified tracing of where a given key was used: the file name can
  identify the service it is used for while the public key's comment (as
  visible in the service's `authorized_keys` file) acts as a back link
  to the holder of the private key
- Potential for plausible deniability not present when a single key is
  used for all services -- same key means same user

At the same time it is advisable to not store private keys in
unencrypted form on any system. Password protection comes to the rescue.

While a password provides security and ease of mind, it is often times
inconvenient: repeated entry of passwords is necessary each and every
time an SSH connection is established.

This is where SSH agents help out, which, upon asking for the key's
password once, will cache the sensitive key material for a specific time
or until the system is rebooted, depending on user preference.


### The Problem

However, with a lot of systems to connect to, each using a separate key
pair for authentication purposes, entering a password for each one of
those -- even if that happens just once over the uptime of a system --
is still a significant burden on the user.


### A Solution

In order to circumvent the repeated entry of passwords for encrypted
keys, why not piggy back on a program available for encryption purposes
on many systems anyway: GnuPG.

**ssh-gpg-agent** acts as an SSH agent that assumes PGP encrypted
private SSH key files and can decrypt those transparently through GnuPG.
Assuming an agent is used for GnuPG keys, decryption of SSH keys can be
demoted to a background activity not requiring any user interaction
whatsoever.

Additionally, if a smart card is used for decryption, there is the added
benefit that simply removing it from the system will also prevent the
automated usage of SSH keys.


Setup
-----

As a first step to using the agent, existing password protected SSH keys
should be re-encrypted with GnuPG.

The following function can be used to simplify the task:
```sh
function encrypt() {
  if [ $# -le 1 ]; then
    echo "Usage: encrypt <ssh-key-file> <gpg-identity-to-encrypt-to>"
    return
  fi

  mkfifo -m 0600 _fifo && \
  (cat "${1}" > _fifo && \
   cat "${1}" > _fifo && \
   gpg --encrypt --recipient="${2}" --yes --output="${1}".gpg < _fifo &) && \
  ssh-keygen -p -N "" -f _fifo && \
  rm _fifo
}
```

This function, applied to a single key, will ask for the key's current
password, decrypt it, and encrypt it to the given GnuPG identity or
recipient.

For example:
```
encrypt '~/.ssh/d-e-s-o@github:access_2018-01-01' 'deso@posteo.net'
```

The result is a new file with the extension `.gpg` that contains the
encrypted key. The original file is left untouched. It can be kept
around as a fall back (e.g., in the case of smart card usage where the
card is not available).

After installation of the agent (through `cargo install ssh-gpg-agent`,
for example) it can be started directly. By default it will work on the
user's `~/.ssh/` directory and it will be used to serve identities that
have an associated `.gpg` file available.

The agent listens for requests in a Unix domain socket, located in the
system's tmp directory with the name `ssh-gpg-agent.sock`.

The `SSH_AUTH_SOCK` environment variable should be pointed to this path
to instruct `ssh` to use **ssh-gpg-agent** if system-wide usage is
desired.

Alternatively, if the agent is to be used only for a subset of hosts,
usage of the agent can be configured to the hosts in question in
`~/.ssh/config`:
```
Host github
  Hostname github.com
  User git
  IdentityFile ~/.ssh/d-e-s-o@github:access_2018-01-01
  # Use ssh-gpg-agent for this host:
  IdentityAgent /tmp/ssh-gpg-agent.sock
```

After this setup, PGP encrypted SSH keys can be transparently decrypted
and used for authentication with a given host.


More Advantages
---------------

Usage of **ssh-gpg-agent** provides a couple more advantages over
typical work flows:
- It is no longer necessary to `ssh-add` keys to an agent, which is just
  an opaque second-tier key management mechanism that often is a source
  of confusion and/or its involvement simply forgotten
- The agent is stateless: public keys are loaded on demand; private keys
  are never cached and instead decrypted for every authentication
  request (note that a `gpg-agent` being used will still be stateful,
  but this agent does not introduce additional state to manage)
- When used in conjunction with a smart card that stores the GnuPG
  identity's key, physically removing the card is enough to prevent
  further usage SSH keys managed through the agent
- It effectively provides a way for multi-factor authentication for the
  usage of SSH keys when used in conjunction with a smart card (physical
  card & PIN in addition to the key itself), which is considered more
  secure than a mere password
- Existing password protected key material can stay as-is and be used as
  a fall back/backup


Limitations
-----------

- Currently only support for ed25519 SSH keys is implemented


Alternative Approaches
----------------------

**ssh-gpg-agent** is only one solution to the stated problem of repeated
password entry when using per-host SSH keys. Alternative ones include:
- Pre-setting of passphrases using the `PRESET_PASSPHRASE` `gpg-agent`
  command (which just adds yet another indirection to the system)
- GnuPG conceptually supports a `protected-shared-secret` key format
  which may or may not be usable to have a shared password among keys
  and perhaps there would be a way to hook this up for SSH keys, but the
  format is not implemented in current versions of GnuPG (i.e., up to
  and including version 2.2)
