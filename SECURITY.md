# Security policy

This alpha spike is for local review only. Do not report or store real OAuth
credentials in issues, fixtures, logs, images, or test volumes. Report a
vulnerability privately to the repository owner before any publication.

The broker's own credentials, the Codex login and a Claude subscription
token, are used only for requests that carry the token of a CI run
registered with an allowed job's GitHub Actions OIDC token, or an operator
token the deployment's tokens file names. Which jobs are allowed is the
deployment's registration policy; its `any_workflow` and `called_workflows`
entries, off unless the policy has them, allow jobs by owner or by a
workflow called from elsewhere rather than one by one, and a token that
registers a run no entry of the policy admits is a vulnerability. A
deployment can opt in, with
`unproven` in its registration policy, to registering runs without that
proof, for whatever reaches the listener; it is off unless the policy says
so, and a run that registers without proof under a policy that lacks it is
a vulnerability. Other Claude
requests are passed through with the caller's own credential, which the
broker forwards and never stores. Read
[INTERNALS.md](INTERNALS.md#credential-modes) and its risks before
deploying.

The one Praxis process that serves Codex Responses also holds the Claude
token, and only its configuration keeps the token on the injected Anthropic
routes. Report anything that gets the broker's credentials used without a
valid run token, the token injected on another route, a caller's credential
or run token forwarded where it was not sent, or any of them logged, as a
vulnerability.
