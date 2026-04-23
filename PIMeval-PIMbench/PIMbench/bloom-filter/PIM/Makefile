PROJ_ROOT = ../../..
include ${PROJ_ROOT}/Makefile.common

EXEC := bloom.out
EXEC_DETECT := detect.out

debug perf dramsim3_integ: $(EXEC) $(EXEC_DETECT)

$(EXEC): bloom.cpp $(DEPS)
	$(CXX) $< $(CXXFLAGS) -o $@

$(EXEC_DETECT): detect.cpp $(DEPS)
	$(CXX) $< $(CXXFLAGS) -o $@

clean:
	rm -rf $(EXEC) $(EXEC_DETECT) *.dSYM
