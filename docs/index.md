---
---

# GlobalPlatform 3.0.0

GlobalPlatform is an open-source C library and command-line tooling for managing
OpenPlatform and GlobalPlatform smart cards. It is used to inspect cards, manage
Security Domains and keys, load Java Card CAP files, and exchange APDUs through
PC/SC readers.

## Features

- Secure channels SCP01, SCP02, SCP03, and SCP11a, including SCP11 certificate,
  CA-KLOC, and public-key provisioning workflows.
- GPShell3 commands for application, load-file, executable-module, Security
  Domain, lifecycle, key, and card-data management.
- Delegated management: token generation and provisioning, DAP verification,
  and AES, DES, RSA, and ECC receipt verification.
- Card Recognition Data, CPLC, extended card-resource, and secure-channel
  capability decoding.
- Extended-length APDUs, multi-command sessions, raw APDU exchange, and a
  PC/SC connection plugin with an extensible plugin interface.

## GPShell

[GPShell3](https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell3.1.md)
is the preferred, task-oriented command-line interface. It is suitable for
interactive use, shell scripts, and CI workflows. The full manual covers SCP11,
delegated management, DAP, receipts, Security Domains, card data, and all
commands.

The script-driven [legacy GPShell manual](https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell.1.md)
remains available for established automation and existing `.txt` scripts.

[GPShell3 demonstration playlist](https://www.youtube.com/watch?v=igqlIvuOB5o&list=PLg46pyBZ2z-wF8acSL1nWvWFU0WPmhwlD)

## Library And SDK

The [C API documentation](api/index.html) is generated from the release source.
The library and its PC/SC plugin are available as CMake packages for developers
embedding GlobalPlatform into their own applications.

The Windows 3.0.0 release includes signed x86 and x64 shared-library SDK ZIP
archives. Each archive contains headers, import libraries, CMake package files,
the GlobalPlatform and PC/SC plugin DLLs, required runtime dependencies, and a
minimal CMake consumer example.

## Installation

Install from [GitHub Releases](https://github.com/kaoh/globalplatform/releases)
for signed Windows installers, Windows SDK archives, Linux DEB/RPM/AppImage
packages, and macOS DMG packages.

For C and CMake projects, use the
[GlobalPlatform vcpkg registry](https://github.com/kaoh/globalplatform-vcpkg-registry).
For macOS and Linux command-line installations, use the
[Homebrew tap](https://github.com/kaoh/homebrew-globalplatform). Manual build
instructions are in the repository [README](https://github.com/kaoh/globalplatform).

## Connection Plugins

The default [PC/SC connection plugin](connectionPlugins.md) supports local smart
card readers. Applications may provide another connection plugin when APDUs are
transported through a remote reader or a virtual-card-reader environment.

## Support And Consulting

Financial support helps maintain the library, GPShell, release infrastructure,
and documentation:

- [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=YPFHYP9P2UK5U&source=url)
- [Patreon](https://www.patreon.com/KarstenOhme)
- [GitHub Sponsors](https://github.com/sponsors/kaoh)
- [FLOSS/Fund](https://dir.floss.fund/view/project/@github.com/kaoh/globalplatform)

Consulting for GlobalPlatform integration, smart-card deployment, and secure
channel workflows is available at [k_o_@users.sourceforge.net](mailto:k_o_@users.sourceforge.net).

## Help And Issues

Report defects through the [GitHub issue tracker](https://github.com/kaoh/globalplatform/issues).
The [SourceForge mailing list](https://sourceforge.net/p/globalplatform/mailman/)
and Stack Overflow tags `gpshell` and `globalplatform` remain available for
community discussion.
