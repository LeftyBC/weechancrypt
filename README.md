# Weechancrypt

Python plugin for Weechat that allows encrypted messages in an IRC channel.
Uses a pre-shared key so all channel members with the correct passphrase
can recieve and send messages.

## Disclaimer

The author(s) of this script are furnishing this item "as is". The author(s) do
not provide any warranty of the item whatsoever, whether express, implied, or
statutory, including, but not limited to, any warranty of merchantability or
fitness for a particular purpose or any warranty that the contents of the item
will be error-free.

In no respect shall the author(s) incur any liability for any damages,
including, but limited to, direct, indirect, special, or consequential damages
arising out of, resulting from, or any way connected to the use of the item,
whether or not based upon warranty, contract, tort, or otherwise; whether or
not injury was sustained by persons or property or otherwise; and whether or
not loss was sustained from, or arose out of, the results of, the item, or any
services that may be provided by the author(s).

The author(s) of this script also do not make any claims about the security of
this script in any way.  Read the code, understand it, and make judgements for
yourself.

## Motivation

IRC (Internet Relay Chat) is an inherently unencrypted, unauthenticated
communications medium.  There have been some attempts to implement encryption
on top of IRC (such as FiSH), or implement IRC-like services that have
encryption and authentication built-in (such as SILC).

One protocol that has gained some widespread acceptance is OTR (Off-The-Record).
Unfortunately, OTR is (by design) a point-to-point system - it can only encrypt
messages between two parties.  This makes OTR excellent for communicating via
private messages, but cannot be used in a group chat system.

Chancrypt is an attempt to implement a protocol that can be used to secure
communications in public channels between parties that have exchanged a
pre-shared key through out-of-band methods, such as the telephone or in person.
Once users have agreed on a pre-shared key, it is then used to encrypt
in-channel messages so that only those users can decode them.  This system can
support a large number of users, since key negotiation happens offline.  In
theory, there should be no upper limit to the number of parties in
the channel.

Chancrypt can be used alongside OTR, and in fact I encourage you to use OTR for
securing privmsg chats.

## Requirements

Requires pycrypto to be installed.  On Debian-like systems, this is usually the
`python-crypto` package, or you can use `pip install pycrypto`.

Requires WeeChat versions newer than 0.3.0.

## Crypto

This plugin uses AES-256 in CFB mode with random per-message IVs.
PBKDF2 is used to derive encryption keys from the user-supplied passphrase.

## Loading

Clone this repo, then run
`ln -s weechancrypt/chancrypt.py ~/.weechat/python/autoload/chancrypt.py` to
enable auto-loading of the script.

Then, in weechat, run `/script load chancrypt.py` to load the script.

## Usage

To enable encrypted messages in a channel, set a passphrase by running:

```/set plugins.var.python.chancrypt.passphrase.<server>.<channel> PASSPHRASE```

This will enable encrypted message support in that channel.
Note that the encryption is opt-in only - if a passphrase is not set, no encryption
or decryption will be attempted.

- Valid *incoming* encrypted messages can be distinguished by the green key icon prefix.
- Invalid messages have a red key icon.
- Unencrypted messages will not have an icon at all.

Users that do not have this plugin will only see a message similar to:

```!ENC c29tZSByYW5kb20gSVY6c29tZSBlbmNyeXB0ZWQgZGF0YQo=```

## Caveats

- This plugin only supports symmetric pre-shared key encryption.
An attacker can decrypt messages in the channel if they have access to this
pre-shared key.
- This plugin does not force encryption in a channel.
Only messages that are prefixed with `!ENC ` will be decrypted, so users that
are joined to the channel and conversing in plaintext will still show up in the
conversation window.
- If different users are using different passphrases in the same channel,
the plugin will complain that the message is invalid for those messages that do
not match the encryption key.
- This plugin is hard-coded to use AES-256 in CTR mode with random IVs.
- This plugin does not take IRC server line-length limits into account at the
moment.  It does compress the ciphertext with zlib before transmitting, but
base64 is not an overly efficient encoding method so that offsets the savings
from zlib somewhat.  In the future I may implement message chunking to avoid
line-length limits.

## Wishlist
Crypto-related:
- Hashed passphrases so they are not stored in plaintext in Weechat configs
- Don't use CRC32 checksums since they're not a cryptographic hash (@kisom
recommends hmac-sha-256 encrypt-then-MAC)
by @kisom)
- Switch to either scrypt or the HKDF from the MAC we pick instead of using
PBKDF2 (as recommended by @kisom)
- Perfect Forward Secrecy with the pre-shared key so an attacker who discovers
the PSK cannot access previous conversations.

UI-related:
- Show a statusbar on the channel's buffer to indicate if encryption for that
channel is enabled
- Show a encryption status prefix on outgoing encrypted messages
- Chunk messages that are larger than the IRC line length limit for the
channel+server
