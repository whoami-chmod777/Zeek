# @TEST-DOC: We don't support a::b as an argument and with in v7.1 this should be an error due args being a record type.

# @TEST-EXEC-FAIL: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

function f(a::b: count) {
	print a::b;  # without this, it's actually fine.
}

event zeek_init()
	{
	f(1);
	}
