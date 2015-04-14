# Weechancrypt

Python plugin for Weechat that allows encrypted messages in an IRC channel.
Uses a pre-shared key so all channel members can recieve and send messages.

## Crypto

This plugin uses AES-256 in CFB mode with random IVs.
PBKDF2 is used to derive encryption keys from the user-supplied passphrase.

## Loading

```/script load chancrypt.py```

## Usage

To enable encrypted messages in a channel, set a passphrase by running:

```/set plugins.var.python.chancrypt.passphrase.<server>.<channel> PASSPHRASE```

This will enable encrypted message support in that channel.

- Valid encrypted messages can be distinguished by the green key icon prefix.
- Invalid messages have a red key icon.
- Unencrypted messages will not have an icon at all.

Users that do not have this plugin will only see a message similar to:

```!ENC c29tZSByYW5kb20gSVY6c29tZSBlbmNyeXB0ZWQgZGF0YQo=```

## Caveats

- This plugin only supports symmetric pre-shared key encryption.  An attacker can decrypt messages in the channel if they have access to this pre-shared key.
- This plugin does not force encryption in a channel.  Only messages that are prefixed with "!ENC " will be decrypted, so users that are joined to the channel and conversing in plaintext will still show up in the conversation window.
- If different users are using different passphrases in the same channel, weechat will display a message that the message is invalid for those messages that do not match the encryption key.
- This plugin is hard-coded to use AES-256 in CFB mode with random IVs.

## Wishlist
- Perfect Forward Secrecy with the pre-shared key so an attacker who discovers the PSK cannot access previous conversations.
- Hashed passphrases so they are not stored in plaintext in Weechat configs
- Don't use CRC32 checksums since they're not a cryptographic hash
- Show a statusbar on the channel's buffer to indicate if encryption for that channel is enabled
