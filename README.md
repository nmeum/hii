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
the code is like full of bugs and very unstable.

## Features

New features (compared to ii):

* Memory safety
* A proper IRC protocol implementation through [girc][girc repo]
* Support for automatically joining channels on startup
* Built-in TLS support
* Built-in IPv6 support

Features intentionally not implemented:

* Automatic authorization using the [PASS command][password message] is
  not implemented (ii `-k` flag). Use authorization using TLS client
  certificates (CertFP) instead. [Most][freenode certfp]
  [IRC][oftc certfp] [networks][hackint certfp] support CertFP.
* Shortcut commands, e.g. `/j`. If you need them write yourself a shell
  script for mapping shortcut commands to real commands.

Planned features include:

* Built-in support for selecting messages matching a given pattern

### Compatibility with ii

Backwards compatibility with ii wasn't a goal. While the directory
structure created by hii is the same as the one created by ii everything
else is pretty much different. This is the case because proper backwards
compatibility would have been a lot of work and I personally
didn't need it.

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
