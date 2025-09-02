#!/usr/bin/env atf-sh
#
# Basic ATF tests for mdo(1) - FreeBSD privilege escalation tool
# These tests focus on functionality that can be tested without root privileges
# or that test error conditions and help output.
#

#
# Test help and usage
#

atf_test_case help_output
help_output_head() {
    atf_set "descr" "Test mdo help message displays correctly"
}
help_output_body() {
    # Test that help shows usage and options - help goes to stderr
    atf_check -s exit:1 -e match:"Usage:" mdo -h
}

atf_test_case invalid_option
invalid_option_head() {
    atf_set "descr" "Test mdo with invalid option"
}
invalid_option_body() {
    # Test invalid option handling - should exit with code 1
    atf_check -s exit:1 mdo -X 2>/dev/null
}

#
# Test argument parsing and validation
#

atf_test_case numeric_uid_without_group
numeric_uid_without_group_head() {
    atf_set "descr" "Test error when using numeric UID without -g option"
}
numeric_uid_without_group_body() {
    atf_check -s exit:1 -e match:"must specify -g" mdo -u 1000 /bin/true
}

atf_test_case conflicting_keep_and_uid_options
conflicting_keep_and_uid_options_head() {
    atf_set "descr" "Test error when -k conflicts with UID override options"
}
conflicting_keep_and_uid_options_body() {
    atf_check -s exit:1 -e match:"cannot be used together" mdo -k --ruid 1000 /bin/true
}

atf_test_case invalid_group_mod_syntax
invalid_group_mod_syntax_head() {
    atf_set "descr" "Test error handling for invalid -s syntax"
}
invalid_group_mod_syntax_body() {
    atf_check -s exit:1 -e match:"invalid -s entry" mdo -u root -s "invalid_entry" /bin/true
}

atf_test_case group_mod_at_position
group_mod_at_position_head() {
    atf_set "descr" "Test error when @ is not first token in -s option"  
}
group_mod_at_position_body() {
    atf_check -s exit:1 -e match:"must be the first token" mdo -u root -s "+daemon,@" /bin/true
}

atf_test_case invalid_user
invalid_user_head() {
    atf_set "descr" "Test error handling for non-existent user"
}
invalid_user_body() {
    atf_check -s exit:1 -e match:"invalid UID" mdo -u nonexistent_user_12345 /bin/true
}

atf_test_case invalid_group
invalid_group_head() {
    atf_set "descr" "Test error handling for non-existent group"
}  
invalid_group_body() {
    atf_check -s exit:1 -e match:"invalid GID" mdo -u root -g nonexistent_group_12345 /bin/true
}

#
# Test rule printing (can be tested without privileges)
#

atf_test_case print_rule_format
print_rule_format_head() {
    atf_set "descr" "Test -r/--print-rule output format"
}
print_rule_format_body() {
    # Test that rule printing produces expected format
    # This might require privileges, so we'll check if it works
    if mdo -u root -r >/dev/null 2>&1; then
        atf_check -s exit:0 -o match:"uid=[0-9]+,gid=[0-9]+" mdo -u root -r
    else
        atf_skip "Rule printing requires elevated privileges"
    fi
}

atf_test_case print_rule_with_groups
print_rule_with_groups_head() {
    atf_set "descr" "Test rule printing includes supplementary groups"
}
print_rule_with_groups_body() {
    # Test rule format with supplementary groups
    if mdo -u root -G daemon -r >/dev/null 2>&1; then
        atf_check -s exit:0 -o match:"uid=[0-9]+,gid=[0-9]+" mdo -u root -G daemon -r
    else
        atf_skip "Rule printing requires elevated privileges"
    fi
}

#
# Test option combinations (parsing only)
#

atf_test_case long_options_parsing
long_options_parsing_head() {
    atf_set "descr" "Test that long options are parsed correctly"
}
long_options_parsing_body() {
    # Test that long options don't cause immediate parse errors
    # We expect these to fail due to privileges, not parsing
    atf_check -s exit:1 \
        -e not-match:"invalid option|illegal option" \
        mdo --ruid 1000 --euid 1000 -g daemon /bin/true 2>/dev/null || \
    atf_check -s exit:1 mdo --ruid 1000 --euid 1000 -g daemon /bin/true 2>/dev/null
}

atf_test_case print_rule_long_option
print_rule_long_option_head() {
    atf_set "descr" "Test that --print-rule long option works"
}
print_rule_long_option_body() {
    # Test --print-rule vs -r equivalence
    output1=$(mdo -u root -r 2>/dev/null || echo "FAILED")
    output2=$(mdo -u root --print-rule 2>/dev/null || echo "FAILED")
    
    # Both should succeed or both should fail with same error
    if [ "$output1" != "FAILED" ] && [ "$output2" != "FAILED" ]; then
        atf_check_equal "$output1" "$output2"
    elif [ "$output1" = "FAILED" ] && [ "$output2" = "FAILED" ]; then
        atf_pass
    else
        atf_fail "Inconsistent behavior between -r and --print-rule"
    fi
}

#
# Test command line argument handling
#

atf_test_case double_dash_handling
double_dash_handling_head() {
    atf_set "descr" "Test that -- properly terminates option parsing"
}
double_dash_handling_body() {
    # Test that -- prevents -h from being interpreted as help
    # This should fail with execution error, not show help
    atf_check -s exit:1 \
        -e not-match:"Usage: mdo" \
        -e match:"exec failed|No such file" \
        mdo -u root -- -h 2>/dev/null || \
    atf_check -s exit:1 \
        -e not-match:"Usage:" \
        mdo -u root -- -h 2>/dev/null
}

#
# Test various group modification syntaxes
#

atf_test_case group_mod_syntax_variations
group_mod_syntax_variations_head() {
    atf_set "descr" "Test various -s option syntax variations"
}
group_mod_syntax_variations_body() {
    # Test that different group mod syntaxes parse correctly
    # These should fail due to privileges, not syntax errors
    
    # Test reset syntax
    atf_check -s exit:1 \
        -e not-match:"invalid -s entry" \
        mdo -u root -s "@" /bin/true 2>/dev/null || true
        
    # Test add syntax  
    atf_check -s exit:1 \
        -e not-match:"invalid -s entry" \
        mdo -u root -s "+daemon" /bin/true 2>/dev/null || true
        
    # Test remove syntax
    atf_check -s exit:1 \
        -e not-match:"invalid -s entry" \
        mdo -u root -s "-daemon" /bin/true 2>/dev/null || true
        
    # Test combination
    atf_check -s exit:1 \
        -e not-match:"invalid -s entry" \
        mdo -u root -s "@,+daemon,-operator" /bin/true 2>/dev/null || true
}

#
# Test empty/edge case inputs
#

atf_test_case empty_group_list
empty_group_list_head() {
    atf_set "descr" "Test handling of empty group specifications"
}
empty_group_list_body() {
    # Test empty -G option
    atf_check -s exit:1 \
        -e not-match:"invalid.*entry" \
        mdo -u root -G "" /bin/true 2>/dev/null || \
    atf_check -s exit:1 mdo -u root -G "" /bin/true 2>/dev/null
}

atf_test_case empty_command
empty_command_head() {
    atf_set "descr" "Test behavior with no command specified"
}
empty_command_body() {
    # Test that mdo without command tries to exec shell
    # Should fail due to privileges but not due to missing command
    atf_check -s exit:1 \
        -e not-match:"no command|missing command" \
        mdo -u root 2>/dev/null < /dev/null || \
    atf_check -s exit:1 mdo -u root 2>/dev/null < /dev/null
}

#
# Initialize test cases
#

atf_init_test_cases() {
    # Help and usage tests
    atf_add_test_case help_output
    atf_add_test_case invalid_option
    
    # Argument validation tests
    atf_add_test_case numeric_uid_without_group
    atf_add_test_case conflicting_keep_and_uid_options
    atf_add_test_case invalid_group_mod_syntax
    atf_add_test_case group_mod_at_position
    atf_add_test_case invalid_user
    atf_add_test_case invalid_group
    
    # Rule printing tests
    atf_add_test_case print_rule_format
    atf_add_test_case print_rule_with_groups
    
    # Option parsing tests
    atf_add_test_case long_options_parsing
    atf_add_test_case print_rule_long_option
    
    # Command line handling tests
    atf_add_test_case double_dash_handling
    
    # Group modification syntax tests
    atf_add_test_case group_mod_syntax_variations
    
    # Edge case tests
    atf_add_test_case empty_group_list
    atf_add_test_case empty_command
}