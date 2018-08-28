FORMATS := html txt
TARGETS := $(foreach ext,$(FORMATS),draft-xchacha-rfc-00.$(ext))

.PHONY: all clean publish
all: $(TARGETS)

publish: all
	mkdir -p pages
	cp $(TARGETS) pages/

clean:
	rm -f $(TARGETS) draft-xchacha-rfc-00.xml
	rm -rf pages

draft-xchacha-rfc-00.xml: xchacha.md
	mmark -xml2 -page $< $@

%.txt: %.xml
	xml2rfc --text $<

%.html: %.xml
	xml2rfc --html $<
