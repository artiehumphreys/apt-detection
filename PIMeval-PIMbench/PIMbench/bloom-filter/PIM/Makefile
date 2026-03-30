PROJ_ROOT = ../../..
include ${PROJ_ROOT}/Makefile.common

EXEC := bloom.out
SRC := bloom.cpp

debug perf dramsim3_integ: $(EXEC)

$(EXEC): $(SRC) $(DEPS)
	$(CXX) $< $(CXXFLAGS) -o $@

clean:
	rm -rf $(EXEC) *.dSYM
