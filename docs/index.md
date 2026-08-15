---
---

# GlobalPlatform 3.0.0

## Summary

GlobalPlatform is an open-source C library and command-line tooling for managing
OpenPlatform and GlobalPlatform smart cards. It is used to inspect cards, manage
Security Domains and keys, load Java Card CAP files, and exchange APDUs through
PC/SC readers.

Highlights:

- Complete GPShell3 SCP11a secure-channel workflow, including certificate,
  CA-KLOC, and elliptic-curve key-agreement provisioning.
- DAP signing and loading through DAP-verifying Security Domains.
- Delegated-management token workflows and receipt verification with AES, DES,
  RSA, and ECC keys.
- Secure channels SCP01, SCP02, SCP03, and SCP11a; extended-length APDUs;
  multi-command sessions; raw APDU exchange; and an extensible PC/SC plugin.

## GPShell

[GPShell3](https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell3.1.md)
is the preferred, task-oriented command-line interface. It is suitable for
interactive use, shell scripts, and CI workflows. The full manual covers SCP11,
delegated management, DAP, receipts, Security Domains, card data, and all
commands.

The script-driven [legacy GPShell manual](https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell.1.md)
remains available for established automation and existing `.txt` scripts.

[GPShell3 example scripts](https://github.com/kaoh/globalplatform/tree/master/gpshell/examples/gpshell3)
and [legacy GPShell scripts](https://github.com/kaoh/globalplatform/tree/master/gpshell/examples/gpshell)
are included with the release packages.

[GPShell3 demonstration playlist](https://www.youtube.com/watch?v=igqlIvuOB5o&list=PLg46pyBZ2z-wF8acSL1nWvWFU0WPmhwlD)

## Support And Consulting

Financial support helps maintain the library, GPShell, release infrastructure,
and documentation:

- [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=YPFHYP9P2UK5U&source=url)
- [Patreon](https://www.patreon.com/KarstenOhme)
- [GitHub Sponsors](https://github.com/sponsors/kaoh)
- [FLOSS/Fund](https://dir.floss.fund/view/project/@github.com/kaoh/globalplatform)

Consulting for GlobalPlatform integration, smart-card deployment, and secure
channel workflows is available at [gpshell@ik.me](mailto:gpshell@ik.me).

## Installation

### GitHub Release Packages

Signed [GitHub Release packages](https://github.com/kaoh/globalplatform/releases)
are available for Windows (MSI, MSIX, and ZIP), Linux (DEB, RPM, and AppImage),
and macOS (DMG).

### vcpkg for C and CMake Projects

For C and CMake projects, use the
[GlobalPlatform vcpkg registry](https://github.com/kaoh/globalplatform-vcpkg-registry).

### Windows SDK

The release page provides signed x86 and x64 Windows shared-library SDK ZIPs.

### Homebrew for Linux and macOS

For Linux and macOS command-line installations, use the
[Homebrew tap](https://github.com/kaoh/homebrew-globalplatform). Manual build
instructions are in the repository [README](https://github.com/kaoh/globalplatform).

## Library And SDK

The [C API documentation](api/index.html) is generated from the release source.
The library and its PC/SC plugin are available as CMake packages for developers
embedding GlobalPlatform into their own applications.

The Windows 3.0.0 release includes signed x86 and x64 shared-library SDK ZIP
archives. Each archive contains headers, import libraries, CMake package files,
the GlobalPlatform and PC/SC plugin DLLs, required runtime dependencies, API
documentation, and a minimal CMake consumer example.

## Connection Plugins

The default [PC/SC connection plugin](connectionPlugins.md) supports local smart
card readers. Applications may provide another connection plugin when APDUs are
transported through a remote reader or a virtual-card-reader environment.

## Help And Issues

Report defects through the [GitHub issue tracker](https://github.com/kaoh/globalplatform/issues).
The [SourceForge mailing list](https://sourceforge.net/p/globalplatform/mailman/)
and Stack Overflow tags `gpshell` and `globalplatform` remain available for
community discussion.
