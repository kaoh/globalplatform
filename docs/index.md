---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults
---

# Overview

The GlobalPlatform card specification is a standard for the management of the contents on a smart card. Mainly this comprises the installation and the removal of applications. Practically these applications are always [JavaCard](http://www.oracle.com/technetwork/java/javacard/overview/index.html)

[This project](https://github.com/kaoh/globalplatform) offers a C library and a command line shell.

Features:

* Install Java Card applets
* Delete Java Java Applet
* List Applications
* Get data
* Manage keys
* Send APDUs

You can support this project with donations. The money will be used for the support of the ongoing development. [Donate](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=YPFHYP9P2UK5U&source=url) using PayPal.

# GPShell

GPShell is the command line utility which can be used to execute the most useful functions.

Inspect the [manual](https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell.1.md) for GPShell.

# GlobalPlatform Library

The C library is called GlobalPlatform. This library is intended for developers who want to integrate it in their own programs using the provided [API](api/index.html).

The most prominent features of the Open and GlobalPlatform specification are implemented supporting the secure channel protocols SCP01, SCP02 and SCP03.
Support for delegated management and DAP verification is implemented in the library but because of missing test data and incomplete card support this might not work.

This [article](globalPlatformSpecification.md) provides an overview of the functions defined in the GlobalPlatform specification.

# Connection Plugins

The GlobalPlatform Library supports different connection plugins. There is a default implementation provided for [PC/SC](http://en.wikipedia.org/wiki/PC/SC) which is the standard for accessing local card readers. See [PC-SC Connection Plugin](connectionPlugins.md). GPShell uses this default implementation. But it is also possible to implement other connection libraries, e.g. to remotely forward APDUs over a socket connection or using a [virtual card reader](http://frankmorgner.github.io/vsmartcard/index.html).

# Installation

There are Homebrew package for [Linux and MacOS](https://github.com/kaoh/homebrew-globalplatform)

For a manual compilation consult the [Readme](https://github.com/kaoh/globalplatform).

For Windows and older version can be downloaded on [SourceForge](https://sourceforge.net/projects/globalplatform/files/GPShell/GPShell-1.4.4/). THis will be updated soon.

# Issues

For issues please use the [GitHub issue tracker](https://github.com/kaoh/globalplatform/issues).

You can also use the [Mailing List](https://sourceforge.net/p/globalplatform/mailman/) or ask a question on Stack Overflow assigning the tags `gpshell` or `globalplatform`.
