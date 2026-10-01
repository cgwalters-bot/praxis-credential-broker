# Security policy

This alpha spike is for local review only. Do not report or store real OAuth
credentials in issues, fixtures, logs, images, or test volumes. Report a
vulnerability privately to the repository owner before any publication.

The optional Anthropic gateway forwards a Claude subscription OAuth token
for any request carrying its public placeholder, with no client
authentication of its own. Keep its listener behind a boundary you control,
and read the risks in
[INTERNALS.md](INTERNALS.md#anthropic-messages-gateway) before enabling it.
