MAINTAINERCLEANFILES = Makefile.in

LANGDIR = $(datadir)/$(PACKAGE_NAME)/languages
LANGUAGES = 	arspanish    italian    mxspanish    portuguese \
		ptbrazilian  spanish    ukenglish    

EXTRA_DIST= ReadMe

install-data-local: 
	@for l in $(LANGUAGES); do \
		$(mkinstalldirs) $(DESTDIR)$(LANGDIR)/$$l && \
		for f in $(srcdir)/$$l/messages $(srcdir)/$$l/template.html $(srcdir)/$$l/fancydmtemplate.html; do \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(LANGDIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(LANGDIR)/$$l; \
		done \
	done

uninstall-local:
	@for l in $(LANGUAGES); do \
		for f in $(srcdir)/$$l/messages $(srcdir)/$$l/template.html $(srcdir)/$$l/fancydmtemplate.html; do \
	        	rm -f $(DESTDIR)$(LANGDIR)/$$l/`basename $$f`; \
		done \
	done

dist-hook:
	@ for lang in $(LANGUAGES); do \
	  if test "$$lang" = .; then :; else \
	    test -d $(distdir)/$$lang \
	    || mkdir $(distdir)/$$lang \
	    || exit 1; \
	    cp -p $(srcdir)/$$lang/messages $(srcdir)/$$lang/template.html $(srcdir)/$$lang/fancydmtemplate.html $(distdir)/$$lang \
	      || exit 1; \
	  fi; \
	done		
