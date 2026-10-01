# Security policy

This alpha spike is for local review only. Do not report or store real OAuth
credentials in issues, fixtures, logs, images, or test volumes. Report a
vulnerability privately to the repository owner before any publication.

The optional Anthropic gateway forwards a Claude subscription OAuth token
for any request to `/anthropic` carrying its public placeholder, with no
client authentication of its own. Keep the listener behind a boundary you
control, and read the risks in
[INTERNALS.md](INTERNALS.md#anthropic-messages-gateway) before enabling it.

With the gateway enabled, the one Praxis process that serves Codex Responses
also holds that token, and only its configuration keeps the token on the
Anthropic routes. Report anything that gets the token injected on another
path, or a client's credentials forwarded where they were not sent, as a
vulnerability.
