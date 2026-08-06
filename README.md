# lsp

The jailed language-server daemon. It holds immutable per-(org, repo, commit)
working trees, runs a language server over each one inside a jail with no
network, and answers position questions about them.

The answer it exists for is a definition that leaves the repository and lands in
a dependency — which a static symbol index structurally cannot give you.

```
POST /root       {org, repo, rev, files}       → {ready, cold, langs}
POST /root/warm  same body, only for a held repo
POST /ask        {org, repo, rev, op, path, line, character, relation}
                                               → the answer, or 409 {"need":"tree"}
GET  /healthz    liveness
GET  /readyz     readiness — green only once the jail proved out on this host
```

Everything else — the wire contract in full, the two-phase security model, the
deployment, and what phase 2 is — is in [LLM.md](LLM.md).
