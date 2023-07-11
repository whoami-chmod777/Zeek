# @TEST-DOC: Adapt in v7.1 and make it an error.

# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module MyModule;

type R: record {
	a::b: string &default="fields with ::";
};

event zeek_init()
	{
	print R();
	}
