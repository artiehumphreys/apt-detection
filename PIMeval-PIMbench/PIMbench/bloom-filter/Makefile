SUBDIRS := PIM

.PHONY: debug perf dramsim3_integ clean $(SUBDIRS)
.DEFAULT_GOAL := perf

debug perf dramsim3_integ clean: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
