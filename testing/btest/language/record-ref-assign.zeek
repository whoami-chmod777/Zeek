# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type State: record {
	host: string &default="NOT SET";
};

global session: State;
global s: State;

event zeek_init()
	{
	s = session;
	s$host = "XXX";
	print s$host, session$host;
	}
