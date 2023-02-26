# hii

A file-based IRC client inspired by [ii(1)][ii homepage].

## Motivation

I originally only intended to write a frontend for ii instead of
completely rewriting it from scratch. However, while working on the
frontend I noticed that I couldn't implement certain features in the
frontend without changes to the backend (ii). I briefly considered
patching ii but ultimately decided for a rewrite.

During the rewrite various features have been implemented which could
have been moved to separate tools, such as TLS support, hence the name
harmful ii (hii).

## Status

I currently consider hii feature complete and use it myself regularly in
combination with with [insomnia][insomnia github] and a per-server
[runit][runit homepage] [user service][runit user] for starting hii.

## Features

New features (compared to ii):

* Memory safety
* A proper IRC protocol implementation through [girc][girc repo]
* Support for automatically joining channels on startup
* Support for [IRCv3.2 monitoring][ircv3.2 monitor]
* Support for a per-channel nick list using a UNIX domain socket
* Support for recording messages mentioning the users
* Support for authentication using TLS client certificates (CertFP)
    * [Most][libera certfp] [IRC][oftc certfp] [networks][hackint certfp] support CertFP
    * This can be used in conjunction with the [SASL EXTERNAL][sasl mechanisms] mechanism
* Built-in TLS support
* Built-in IPv6 support

Features intentionally not implemented:

* Automatic authorization using the [PASS command][password message] is
  not implemented (ii `-k` flag).
* Shortcut commands, e.g. `/j`. If you need them write yourself a shell
  script for mapping shortcut commands to real commands.

While hii has more features than ii it is still supposed to have a limit
feature set and shouldn't ["expand until it can read mail"][jwz's law].

### Compatibility with ii

Backwards compatibility with ii wasn't a goal. While the directory
structure is mostly backwards compatible everything else is pretty much
different. This is the case because proper backwards compatibility would
have been a lot of work and I personally didn't need it.

## Installation

The program can be installed either using `go install` or `make`.

### go install

To install to the program using `go install` run the following commands:

	$ git clone https://github.com/nmeum/hii.git
	$ cd hii
	$ go install

### make

To install to the program using `make` run the following commands:

	$ git clone https://github.com/nmeum/hii.git
	$ cd hii
	$ make && make install

This will also install documentation files to the correct location and
may thus be preferable when packaging this software for a distribution.

## FAQ

**Q:** Sockets cannot be used with standard utilities such as `grep(1)`.
Why are nick names served using a unix domain socket anyhow?

**A:** Several ways of implementing a nick list have been considered.
Using a regular file has various obvious disadvantages. For instance,
the file would need to be truncated every time the nick list changes,
which causes a lot of file system operation. Using a FUSE for serving
the nick list was also briefly considered, however, while this would
allow interaction with standard utilities it would require linking
against FUSE and would complicate things quite a bit. Serving nicks
using a unix domain socket seemed to be a reasonable compromise.

**Q:** Why are mentions recorded in a separate file? Can't this be
implemented using inotify, kqueue, … in the frontend?

**A:** While this might certainly be possible it would complicate the
frontend code quite a bit. Implementing this in the backend was fairly
easy and only required a few changes. Additionally, neither kqueue nor
inotify are mandated by POSIX.

**Q:** Can feature X/Y/Z be added to hii?

**A:** No.

## License

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.

[ii homepage]: https://tools.suckless.org/ii/
[girc repo]: https://github.com/lrstanley/girc
[password message]: https://tools.ietf.org/html/rfc1459#section-4.1.1
[libera certfp]: https://libera.chat/guides/certfp
[oftc certfp]: https://www.oftc.net/NickServ/CertFP/
[hackint certfp]: https://www.hackint.org/services#NickServ
[jwz's law]: https://en.wikipedia.org/wiki/Zawinski's_law_of_software_envelopment#Principles
[ircv3.2 monitor]: https://ircv3.net/specs/core/monitor-3.2.html
[insomnia github]: https://github.com/nmeum/insomnia
[runit homepage]: http://smarden.org/runit/
[runit user]: http://smarden.org/runit/faq.html#userservices
[sasl mechanisms]: https://ircv3.net/docs/sasl-mechs
