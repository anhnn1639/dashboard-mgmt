# Codex project instructions

Before changing this repository, read `CODEX_HANDOFF.md` completely. It records the live deployment state, the latest agent authentication work, known issues, and the user's outstanding requirements.

Project-specific rules:

- The user has explicitly authorized pushing each completed change directly to `main`.
- Inspect `git status` and the diff first; never overwrite unrelated local changes.
- Keep all durable application data in PostgreSQL. Do not introduce SQLite or browser storage for server-side state.
- Keep normal dashboard access on HTTP as requested. Port `9443` is reserved for the agent's HTTPS/mTLS control channel.
- Never commit `.env`, enrollment tokens, passwords, private keys, LDAP bind secrets, database URLs containing passwords, or generated recordings.
- Treat remote administration features as security-sensitive: validate input, use allowlisted actions, keep audit trails, and preserve approval checks.
- Run the most relevant tests before every commit. After pushing, verify that remote `main` points to the new commit.
- Update `CODEX_HANDOFF.md` whenever deployment state, known issues, or the next required action changes materially.

