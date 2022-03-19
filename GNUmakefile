NAME = hii

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
DOCDIR ?= $(PREFIX)/share/doc/$(NAME)

$(NAME):
	go build -trimpath -o $@

install: $(NAME) $(NAME).1 $(NAME).5 README.md
	install -Dm755 $(NAME) "$(DESTDIR)$(BINDIR)/$(NAME)"
	install -Dm644 $(NAME).1 "$(DESTDIR)$(MANDIR)/man1/$(NAME).1"
	install -Dm644 $(NAME).5 "$(DESTDIR)$(MANDIR)/man5/$(NAME).5"
	install -Dm644 README.md "$(DESTDIR)$(DOCDIR)/README.md"

.PHONY: install $(NAME)
