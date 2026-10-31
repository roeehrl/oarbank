# Security policy

Oarbank runs other people's code on your computers, so security reports matter more than most. Thank you for
sending one.

## Reporting a vulnerability

Report it privately, never in a public issue, discussion or pull request:

- **GitHub:** [Report a vulnerability](https://github.com/roeehrl/oarbank/security/advisories/new) on this
  repository's Security tab, or
- **Email:** support@codonic.dev, with "security" in the subject.

Say what you found, which version and operating system, and how to reproduce it. A proof of concept helps but isn't
required. Please give us a reasonable time to ship a fix before you publish; we'll agree a date with you and credit
you in the advisory and the changelog unless you'd rather not be named.

## What's in scope

The core in this repository: the coordinator (`oarbankd`), its console and CLI, the node agent and launcher, the
installers, and the update and signing paths. Especially:

- a job escaping its sandbox (Seatbelt on macOS, Landlock and seccomp on Linux, AppContainers on Windows), or reaching
  files, hosts, devices or containers its module version wasn't granted
- a node, module or job acting with the owner's authority without the owner's signature
- joining a fleet, or reading or changing its work, without a valid join code or account
- a node's results counting before it is certified, or a stale or forged result being accepted
- the console: authentication, sessions, CSRF, or cross-site scripting

Modules are separate projects: report a module's own bugs to its author. Bugs in the
[module SDK](https://github.com/roeehrl/oarbank-sdk) go to that repository's Security tab.

## Supported versions

Fixes go into the latest release line. Today that is **2.11.x**; older lines don't get security fixes, so upgrade
to the latest release ([Upgrading](https://docs.codonic.dev/oarbank/operate/upgrading)).
