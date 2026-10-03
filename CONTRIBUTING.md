# Contributing to Oarbank

Thank you for helping. Oarbank's core is source-available under the PolyForm Strict License 1.0.0
([LICENSE.md](LICENSE.md)): you may read it and use it for noncommercial purposes, but not change it, build new works
on it or distribute it. Commercial use needs a license from Codonic (support@codonic.dev). The module SDK in
`vendor/oarbank-sdk` is a separate project under the Apache License 2.0.

## Permission to contribute

Notwithstanding LICENSE.md, Codonic Dev, LLC grants you permission to fork this repository on GitHub and to make
changes to your copy **only** to prepare, test and submit contributions back to this repository. This permission
does not let you use the changed software for any other purpose, publish or distribute it anywhere else, or keep
using it once your contribution is merged or declined. It ends if you break these terms or the license.

## The Contributor License Agreement

Before a pull request can be merged you sign the [Contributor License Agreement](CLA.md) (once; the CLA bot asks on
your first pull request). It lets Codonic ship your contribution under the project's license and its commercial
licenses. You keep the copyright in your work.

## Making a change

- Open an issue first for anything larger than a small fix, so we can agree on the approach.
- Keep the existing style; add tests next to the code you change; run `uv run --extra dev pytest` and
  `(cd rust && cargo test --workspace)`.
- Security problems go to support@codonic.dev, not to a public issue.
