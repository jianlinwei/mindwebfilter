MAINTAINERCLEANFILES = Makefile.in \
		       clamav.conf clamdscan.conf icapscan.conf \
		       kavav.conf kavdscan.conf commandlinescan.conf

DGDATADIR = $(DGCONFDIR)/contentscanners

SUBDIRS = .


FLISTS = 

if ENABLE_CLAMD
FLISTS += clamdscan.conf
endif

if HAVE_CLAMAV
FLISTS += clamav.conf
endif

if ENABLE_ICAP
FLISTS += icapscan.conf
endif

if ENABLE_KAVD
FLISTS += kavdscan.conf
endif

#if HAVE_KAVCLIENT
#FLISTS += kavav.conf
#endif

if ENABLE_COMMANDLINE
FLISTS += commandlinescan.conf
endif

EXTRA_DIST = clamav.conf.in clamdscan.conf.in icapscan.conf.in \
             kavav.conf.in kavdscan.conf.in commandlinescan.conf.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(DGDATADIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DGDATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DGDATADIR)/$$l; \
	done


uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DGDATADIR)/$$l ; \
	done
