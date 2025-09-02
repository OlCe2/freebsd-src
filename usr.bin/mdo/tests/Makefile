# Makefile for mdo(1) ATF tests
#
# This Makefile helps build and run the ATF test suite for mdo

.include <bsd.own.mk>

# Test programs
ATF_TESTS_SH=	mdo_test mdo_basic_test

# Test files
FILESDIR=	${TESTSDIR}
FILES=		Kyuafile

# Make the tests executable
CLEANFILES=	mdo_test mdo_basic_test

# Set up Kyua environment for non-root users
KYUA_ENV=	KYUA_CONFDIR="${HOME}/.kyua" KYUA_VARIABLE_DIR="${HOME}/.kyua"

# Build rules
mdo_test: mdo_test.sh
	cp ${.ALLSRC} ${.TARGET}
	chmod +x ${.TARGET}

mdo_basic_test: mdo_basic_test.sh  
	cp ${.ALLSRC} ${.TARGET}
	chmod +x ${.TARGET}

# Include ATF test framework
.include <bsd.test.mk>

# Custom targets for development/testing

# Ensure kyua directories exist
.kyua-setup:
	@mkdir -p "${HOME}/.kyua/logs"
	@touch .kyua-setup

# Run just the basic tests (non-root friendly)
test-basic: mdo_basic_test .kyua-setup
	${KYUA_ENV} kyua test mdo_basic_test

# Run all tests (requires root)
test-all: mdo_test mdo_basic_test .kyua-setup
	${KYUA_ENV} kyua test

# Run specific test case
test-case: mdo_test .kyua-setup
	@if [ -z "$(CASE)" ]; then \
		echo "Usage: make test-case CASE=<test_case_name>"; \
		exit 1; \
	fi
	${KYUA_ENV} kyua test mdo_test:$(CASE)

# List all available test cases
list-tests: mdo_test mdo_basic_test
	@echo "Basic tests (non-root friendly):"
	@grep "atf_test_case " mdo_basic_test.sh | sed 's/atf_test_case /  /' | sed 's/_head.*//'
	@echo
	@echo "Full tests (require root):"  
	@grep "atf_test_case " mdo_test.sh | sed 's/atf_test_case /  /' | sed 's/_head.*//'

# Clean up test artifacts
clean-tests:
	rm -f mdo_test mdo_basic_test .kyua-setup
	${KYUA_ENV} kyua db-exec "DELETE FROM test_results" 2>/dev/null || true

# Show test results
show-results: .kyua-setup
	${KYUA_ENV} kyua report --verbose

# Show only failed tests
show-failures: .kyua-setup
	${KYUA_ENV} kyua report --verbose --results-filter=broken,failed

# Install tests to system test directory
install: all
	mkdir -p $(DESTDIR)$(TESTSDIR)
	cp mdo_test mdo_basic_test Kyuafile $(DESTDIR)$(TESTSDIR)

.PHONY: test-basic test-all test-case list-tests clean-tests show-results show-failures install-tests
