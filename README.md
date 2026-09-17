# extmilter

A Postfix milter service that blocks messages carrying attachments with
executable or otherwise dangerous file extensions — including attachments
hidden inside nested archives (`.zip`, `.tar`, `.rar`) or nested email
messages (`message/rfc822` parts).

## How it works

extmilter only ever inspects **multipart** messages; anything that isn't
`multipart/*` is accepted immediately without further processing (a plain
text/HTML email has no attachments to check).

For multipart messages:

1. Headers and body are buffered in memory as the milter streams them in
   (`Header`, `Headers`, `BodyChunk` callbacks).
2. At end-of-message (`Body`), the buffered message is parsed as a real
   `net/mail` message and walked with `mime/multipart`.
3. For every part that has a filename (i.e. looks like an attachment):
   - The filename is decoded if it uses RFC 2047 encoded-word syntax
     (`=?charset?...?=`), with explicit support for `koi8-r` and
     `windows-1251` charsets on top of Go's built-in decoders — needed
     because a lot of older mail clients tag Cyrillic filenames this way.
   - The file extension is checked against a hardcoded blacklist (see
     below). If blacklisted, the message is rejected outright with a
     custom `552` SMTP response.
   - If the attachment itself is a `tar`, `zip`, or `rar` archive, its
     contents are inspected recursively (including archives nested inside
     archives) so a blacklisted file can't be smuggled in a `.zip` disguised
     as a harmless-looking outer attachment.
   - If a part is itself a `message/*` (a forwarded/attached email), it is
     parsed recursively the same way.

Unlike bogomilter, extmilter can **reject** a message outright (SMTP `552`),
since a blacklisted attachment is treated as a hard policy violation rather
than something to tag and let downstream systems decide about.

### Blacklisted extensions

Hardcoded in `parser.go` (`ExtensionBlacklist`):

```
.asd .bat .chm .cmd .com .dll .do .exe .hlp .hta .js .jse .lnk .ocx
.pif .reg .scr .shb .shm .shs .vbe .vbs .vbx .vxd .wsf .wsh .xl .jar
```

Changing this list currently requires editing the source and rebuilding —
there is no config file or flag for it.

## Command-line flags

| Flag | Default | Description |
|---|---|---|
| `-proto` | `unix` | Socket family to listen on: `unix` or `tcp` |
| `-addr` | `/var/spool/postfix/milters/ext.sock` | Address or unix socket path to bind to |

## Postfix integration

```
smtpd_milters =
  ...,
  unix:milters/ext.sock
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
```

As with the other milters here, the socket path is relative to Postfix's
`queue_directory`, so `unix:milters/ext.sock` resolves to
`/var/spool/postfix/milters/ext.sock`.

## Deployment

Runs as a standalone systemd service (see `extmilter.service`) as the
`postfix` user/group.

Build with a recent Go toolchain (module-aware, Go ≥ 1.21):

```sh
go build -o extmilter .
```

Dependencies (see `go.mod`):
- `github.com/phalaaxx/milter` — milter protocol implementation
- `github.com/nwaples/rardecode` — RAR archive reading, for inspecting `.rar` attachments
- `golang.org/x/text` — charmap decoders for legacy Cyrillic attachment filenames

## Known limitations

- The extension blacklist and the set of inspected archive formats
  (tar/zip/rar) are hardcoded; there's no per-domain or per-recipient
  policy.
- Archive inspection reads whole nested payloads into memory (no size
  limits), which is fine at current mail volumes but would need bounding
  before use on a high-traffic mail server.
