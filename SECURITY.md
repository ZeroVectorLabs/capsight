# Security Policy

## Reporting a vulnerability

Deepacket parses untrusted capture files in your browser, so a crafted capture that runs script in the page, leaks data, or makes the decoders misbehave is a security issue.

Please do not open a public issue for it. Report it privately instead: go to the **Security** tab of this repository and click **Report a vulnerability**.

Include:

- the Deepacket version or commit
- your browser and its version
- a minimal capture that reproduces the problem (strip anything sensitive first)
- what you expected and what happened

You will get a reply as soon as possible, and credit in the release notes once a fix ships, unless you prefer not to be named.

## Scope

In scope: the capture readers and protocol decoders, file carving and artifact export, and how capture data is rendered in the page.

Out of scope: findings that need a modified copy of Deepacket, and denial of service from captures larger than the browser can hold in memory (see Limitations in the README).
