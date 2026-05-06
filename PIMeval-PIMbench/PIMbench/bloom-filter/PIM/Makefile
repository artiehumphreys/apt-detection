PROJ_ROOT = ../../..
include ${PROJ_ROOT}/Makefile.common

EXEC := bloom.out
EXEC_DETECT := detect.out
EXEC_FPGA_COMPARE := bloom_fpga_compare.out

debug perf dramsim3_integ: $(EXEC) $(EXEC_DETECT)

$(EXEC): bloom.cpp $(DEPS)
	$(CXX) $< $(CXXFLAGS) -o $@

$(EXEC_DETECT): detect.cpp $(DEPS)
	$(CXX) $< $(CXXFLAGS) -o $@

fpga_compare: CXXFLAGS += -O3 -Wno-unknown-pragmas
fpga_compare: $(EXEC_FPGA_COMPARE)

$(EXEC_FPGA_COMPARE): bloom_fpga_compare.cpp $(DEPS)
	$(CXX) $< $(CXXFLAGS) -o $@

clean:
	rm -rf $(EXEC) $(EXEC_DETECT) $(EXEC_FPGA_COMPARE) *.dSYM
