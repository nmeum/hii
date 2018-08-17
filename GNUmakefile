NAME = hii

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
DOCDIR ?= $(PREFIX)/share/doc/$(NAME)

IMPORTPATH=src/github.com/nmeum/$(NAME)
export GOPATH="$(CURDIR)"

$(NAME): $(IMPORTPATH)
	cd $< && go build -o $@
$(IMPORTPATH): $(GOPATH)
	mkdir -p $(shell dirname $@)
	ln -fs $< $@

install: $(NAME) $(NAME).1 README.md
	install -Dm755 $(NAME) "$(DESTDIR)$(BINDIR)/$(NAME)"
	install -Dm644 $(NAME).1 "$(DESTDIR)$(MANDIR)/man1/$(NAME).1"
	install -Dm644 README.md "$(DESTDIR)$(DOCDIR)/README.md"

.PHONY: install $(NAME)
