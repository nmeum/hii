NAME = hii

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
DOCDIR ?= $(PREFIX)/share/doc/$(NAME)

$(NAME):
	go build -trimpath -o $@

install: $(NAME) $(NAME).1 README.md
	install -Dm755 $(NAME) "$(DESTDIR)$(BINDIR)/$(NAME)"
	install -Dm644 $(NAME).1 "$(DESTDIR)$(MANDIR)/man1/$(NAME).1"
	install -Dm644 $(NAME).5 "$(DESTDIR)$(MANDIR)/man5/$(NAME).5"
	install -Dm644 README.md "$(DESTDIR)$(DOCDIR)/README.md"

dist: VERSION = $(shell git describe --tags)
dist:
	mkdir -p $(NAME)-$(VERSION)
	cp -R hii.go hii.1 hii.5 README.md LICENSE.md vendor GNUmakefile go.mod $(NAME)-$(VERSION)
	find $(NAME)-$(VERSION) -name '.git' -exec rm -rf {} +
	tar -czf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

.PHONY: install dist $(NAME)
