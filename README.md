# hii

Harmful [ii(1)][ii homepage] as known as ii for humans.

## Motivation

I originally only intended to write a frontend for ii instead of
completely rewriting it from scratch. However, while working on the
frontend I noticed that I couldn't implement certain features in the
frontend without changes to the backend (ii). I briefly considered
patching ii but ultimately decided for a rewrite since I could also
achieve memory safety while at it.

## Status

This is work in progress. At the moment this is a rather incomplete
reimplementation of ii, supporting a subset of the features supported by
ii. The current plan is to cleanup and improve the existing code base
before starting to implement more of the planned features listed below.

This cleanup involves increasing backwards compatibility with ii and
figure out how much backwards compatibility should be provided.

## Compatibility with ii

hii is not entirely backwards compatibly with ii. The directory
structure and the output emitted on `out` files should be compatible
with ii everything else pretty much isn't. In the following
incompatibilities with ii are described further.

The following properties of ii were not implemented intentionally:

* Automatic authorization using the [PASS command][password message] is
  not implemented (ii `-k` flag). Use authorization using TLS client
  certificates (CertFP) instead. [Most][freenode certfp]
  [IRC][oftc certfp] [networks][hackint certfp] support CertFP.
* Data received from the IRC server is not emitted on standard output.

The following properties of ii are currently not implemented. However,
they *may* be implemented in future version of hii:

* The mapping of data received from the IRC server to `out` files is not
  entirely the same. Meaning ii will write certain commands to the
  server `out` file while hii will write them to a channel specific
  `out` file and vice versa.
* The format used for data written to `out` files differs. hii writes
  currently writes raw server responses to the file while ii transform
  the received responses a bit.

## Features

New features (compared to ii):

* Memory safety
* Partial compatibility with ii
* Built-in IPv6 support
* A proper protocol implementation through [girc][girc repo]
* Automatically joining channels on startup

Planned features include:

* Built-in TLS support
* Built-in support for selecting messages matching a given pattern

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
