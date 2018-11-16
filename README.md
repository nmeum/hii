# hii

Harmful [ii(1)][ii homepage] also known as ii for humans.

## Motivation

I originally only intended to write a frontend for ii instead of
completely rewriting it from scratch. However, while working on the
frontend I noticed that I couldn't implement certain features in the
frontend without changes to the backend (ii). I briefly considered
patching ii but ultimately decided for a rewrite since I could also
achieve memory safety while at it.

## Status

This is work in progress. Some of the features I intended to add to ii
are already implemented, others aren't. Besides, I am currently not
using this myself since I didn't finish work on the frontend yet, thus
the code is likely full of bugs and very unstable.

## Features

New features (compared to ii):

* Memory safety
* A proper IRC protocol implementation through [girc][girc repo]
* Support for automatically joining channels on startup
* Support for a per-channel nick list using a UNIX domain socket
* Support for recording messages mentioning the users
* Built-in TLS support
* Built-in IPv6 support

Features intentionally not implemented:

* Automatic authorization using the [PASS command][password message] is
  not implemented (ii `-k` flag). Use authorization using TLS client
  certificates (CertFP) instead. [Most][freenode certfp]
  [IRC][oftc certfp] [networks][hackint certfp] support CertFP.
* Shortcut commands, e.g. `/j`. If you need them write yourself a shell
  script for mapping shortcut commands to real commands.

While hii certainly has more features than ii it is still supposed to
have a limit feature set and shouldn't ["expand until it can read mail"]
[jwz's law].

### Compatibility with ii

Backwards compatibility with ii wasn't a goal. While the directory
structure is backwards compatible everything else is pretty much
different. This is the case because proper backwards compatibility would
have been a lot of work and I personally didn't need it.

## Installation

The program can be installed either using `go get` or `GNU make`. The
latter automatically setups a `GOPATH` and thus doesn't require the go
toolchain to be configured properly.

### go get

To install to the program using `go get` run the following command:

	$ go get github.com/nmeum/hii

### GNU make

To install it using `GNU make`, which is the preferred way when
packing this software for a distribution, run the following commands:

	$ make
	$ make install

## FAQ

**Q:** Sockets cannot be used with standard utilities such as `grep(1)`.
Why are nick names served using a unix domain socket anyhow?

**A:** Several ways of implementing a nick list have been considered.
Using a regular file has various obvious disadvantages. To name a few:
The file would need to be truncated every time the nick list changes,
doing so would cause a lot of file system operation and would require
file locking. Using a FUSE for serving the nick list was also briefly
considered, however, while this would allow interaction with standard
utilities it would require linking against FUSE and would complicate
things quite a bit. Serving nick using a unix domain socket seemed to be
a reasonable compromise.

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

[ii homepage]: https://tools.suckless.org/
[girc repo]: https://github.com/lrstanley/girc
[password message]: https://tools.ietf.org/html/rfc1459#section-4.1.1
[freenode certfp]: https://freenode.net/kb/answer/certfp
[oftc certfp]: https://www.oftc.net/NickServ/CertFP/
[hackint certfp]: https://www.hackint.org/services#NickServ
[jwz's law]: https://en.wikipedia.org/wiki/Zawinski's_law_of_software_envelopment#Principles
