# Contributing

Thanks for helping. Bug reports, fixes and new scanner examples are all welcome.

## Before you open a pull request

1. **Open an issue first** for anything bigger than a small fix, so we can agree on the change.
2. **Keep the standard library only.** The script must run on a clean Python 3.9+ with nothing to install.
3. **Add a test** for new logic in `tests/test_vuln_fix_first.py`. Tests must not call the network.
4. **Run the tests:**
   ```
   python tests/test_vuln_fix_first.py
   ```
5. **Update the docs** when you change behavior: `README.md` for people, `SKILL.md` for the agent.

## Style

- Everything in English: code, comments, docs, commits and issues.
- Write for beginners and experts at once: explain each term in plain words the first time, and keep commands, names and numbers exact.
- Short functions, short comments that explain *why*, not *what*.

## Decision tables

The SSVC tables in the script are copied from the [CERT/CC SSVC project](https://github.com/CERTCC/SSVC). Don't edit their rows by hand. If CISA publishes a new version, update the table from the source CSV and say which version in the comment above it.

## License

By contributing, you agree that your work is released under the [MIT License](LICENSE).
