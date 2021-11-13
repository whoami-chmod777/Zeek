// This code contributed by Nadi Sarrar.

#include "zeek/analyzer/protocol/bittorrent/BitTorrentTracker.h"

#include <sys/types.h>
#include <algorithm>

#include "zeek/RE.h"
#include "zeek/analyzer/protocol/bittorrent/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#define FMT_INT "%" PRId64
#define FMT_UINT "%" PRIu64

namespace zeek::analyzer::bittorrent
	{

static TableTypePtr bt_tracker_headers;
static RecordTypePtr bittorrent_peer;
static TableTypePtr bittorrent_peer_set;
static RecordTypePtr bittorrent_benc_value;
static TableTypePtr bittorrent_benc_dir;

BitTorrentTracker_Analyzer::BitTorrentTracker_Analyzer(Connection* c)
	: analyzer::tcp::TCP_ApplicationAnalyzer("BITTORRENTTRACKER", c)
	{
	if ( ! bt_tracker_headers )
		{
		bt_tracker_headers = id::find_type<TableType>("bt_tracker_headers");
		bittorrent_peer = id::find_type<RecordType>("bittorrent_peer");
		bittorrent_peer_set = id::find_type<TableType>("bittorrent_peer_set");
		bittorrent_benc_value = id::find_type<RecordType>("bittorrent_benc_value");
		bittorrent_benc_dir = id::find_type<TableType>("bittorrent_benc_dir");
		}

	keep_alive = false;

	req_state = detail::BTT_REQ_GET;
	req_buf[sizeof(req_buf) - 1] = 0;
	req_buf_pos = req_buf;
	req_buf_len = 0;
	req_val_uri = nullptr;
	req_val_headers = new TableVal(bt_tracker_headers);

	res_state = detail::BTT_RES_STATUS;
	res_allow_blank_line = false;
	res_buf[sizeof(res_buf) - 1] = 0;
	res_buf_pos = res_buf;
	res_buf_len = 0;
	res_status = 0;
	res_val_headers = new TableVal(bt_tracker_headers);
	res_val_peers = new TableVal(bittorrent_peer_set);
	res_val_benc = new TableVal(bittorrent_benc_dir);

	InitBencParser();

	stop_orig = false;
	stop_resp = false;
	}

BitTorrentTracker_Analyzer::~BitTorrentTracker_Analyzer()
	{
	Unref(req_val_uri);
	Unref(req_val_headers);

	Unref(res_val_headers);
	Unref(res_val_peers);
	Unref(res_val_benc);

	benc_stack.clear();
	benc_count.clear();
	}

void BitTorrentTracker_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();
	}

void BitTorrentTracker_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	if ( orig )
		ClientRequest(len, data);
	else
		ServerReply(len, data);
	}

void BitTorrentTracker_Analyzer::ClientRequest(int len, const u_char* data)
	{
	if ( stop_orig )
		return;

	if ( req_buf_len + len > sizeof(req_buf) - 1 )
		{
		ProtocolViolation("BitTorrentTracker: request message too long");
		stop_orig = true;
		return;
		}

	memcpy(&req_buf[req_buf_len], data, len);
	req_buf_len += len;
	req_buf[req_buf_len] = 0;

	while ( req_buf_pos < req_buf + req_buf_len )
		{
		char* lf = strchr(req_buf_pos, '\n');
		if ( ! lf )
			break;
		*lf = 0;

		char* cr = strrchr(req_buf_pos, '\r');
		if ( cr )
			*cr = 0;

		if ( ! ParseRequest(req_buf_pos) )
			return;

		req_buf_pos = lf + 1;

		if ( req_state == detail::BTT_REQ_DONE && keep_alive )
			{
			req_state = detail::BTT_REQ_GET;
			req_buf_len -= (req_buf_pos - req_buf);
			memmove(req_buf, req_buf_pos, req_buf_len);
			req_buf_pos = req_buf;
			req_val_headers = new TableVal(bt_tracker_headers);
			}
		}
	}

void BitTorrentTracker_Analyzer::ServerReply(int len, const u_char* data)
	{
	if ( stop_resp )
		return;

	if ( res_state == detail::BTT_RES_DONE )
		// We are done already, i.e. state != 200.
		return;

	if ( res_buf_len + len > sizeof(res_buf) - 1 )
		{
		ProtocolViolation("BitTorrentTracker: response message too long");
		stop_resp = true;
		return;
		}

	memcpy(&res_buf[res_buf_len], data, len);
	res_buf_len += len;
	res_buf[res_buf_len] = 0;

	while ( true )
		{
		while ( res_state != detail::BTT_RES_BODY && res_buf_pos < res_buf + res_buf_len )
			{
			char* lf = strchr(res_buf_pos, '\n');
			if ( ! lf )
				break;
			*lf = 0;

			char* cr = strrchr(res_buf_pos, '\r');
			if ( cr )
				*cr = 0;

			if ( ! ParseResponse(res_buf_pos) )
				return;

			res_buf_pos = lf + 1;
			}

		if ( res_state != detail::BTT_RES_BODY || res_buf_pos >= res_buf + res_buf_len )
			break;

		ResponseBody();

		if ( res_state != detail::BTT_RES_DONE || res_status != 200 || ! keep_alive )
			break;

		res_state = detail::BTT_RES_STATUS;
		res_allow_blank_line = true;
		res_buf_len -= res_buf_pos - res_buf;
		memmove(res_buf, res_buf_pos, res_buf_len);
		res_buf_pos = res_buf;
		res_status = 0;

		res_val_headers = new TableVal(bt_tracker_headers);
		res_val_peers = new TableVal(bittorrent_peer_set);
		res_val_benc = new TableVal(bittorrent_benc_dir);

		InitBencParser();
		}
	}

void BitTorrentTracker_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

	ProtocolViolation("BitTorrentTracker: cannot recover from content gap");

	if ( orig )
		stop_orig = true;
	else
		stop_resp = true;
	}

void BitTorrentTracker_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	}

void BitTorrentTracker_Analyzer::InitBencParser(void)
	{
	benc_stack.clear();
	benc_count.clear();

	benc_state = detail::BENC_STATE_EMPTY;
	benc_raw = nullptr;
	benc_raw_type = detail::BENC_TYPE_NONE;
	benc_raw_len = 0;
	benc_key = nullptr;
	benc_key_len = 0;
	benc_strlen = nullptr;
	benc_str = nullptr;
	benc_str_len = 0;
	benc_str_have = 0;
	benc_int = nullptr;
	benc_int_val = 0;
	}

void BitTorrentTracker_Analyzer::DeliverWeird(const char* msg, bool orig)
	{
	if ( bt_tracker_weird )
		EnqueueConnEvent(bt_tracker_weird, ConnVal(), val_mgr->Bool(orig),
		                 make_intrusive<StringVal>(msg));
	}

bool BitTorrentTracker_Analyzer::ParseRequest(char* line)
	{
	static bool initialized = false;
	static RE_Matcher re_get("^GET[ \t]+");
	static RE_Matcher re_get_end("[ \t]+HTTP/[0-9.]+$");
	static RE_Matcher re_hdr("^[^: \t]+:[ ]*");

	if ( ! initialized )
		{
		re_get.Compile();
		re_get_end.Compile();
		re_hdr.Compile();

		re_get.MakeCaseInsensitive();
		re_get_end.MakeCaseInsensitive();
		re_hdr.MakeCaseInsensitive();

		initialized = true;
		}

	switch ( req_state )
		{
		case detail::BTT_REQ_GET:
			{
			int len_get;
			// 1. Get length of the match using MatchPrefix()
			// 2. Check if the len_get is not -1
			// 3. If len_get is not -1, then continue otherwise throw error
			if ( (len_get = re_get.MatchPrefix(line)) == -1 )
				{
				ProtocolViolation("BitTorrentTracker: invalid HTTP GET");
				stop_orig = true;
				return false;
				}

			int len_get_end, match_end;

			// 1. Get the starting position of the match using MatchAnywhere()
			// 2. Check if the match_end is greater than 0
			// 3. If match_end is greater than 0, then there is a match
			if ( (match_end = re_get_end.MatchAnywhere(line)) > 0 )
				{
				// 4. Get the length of the match using MatchPrefix()
				// 5. Check if match_end is greater than len_get otherwise throw error
				len_get_end = re_get_end.MatchPrefix(line);
				if ( match_end <= len_get )
					{
					ProtocolViolation("BitTorrentTracker: invalid HTTP GET");
					stop_orig = true;
					return false;
					}
				// To keep_alive check the last char of the matched string
				// last char = match_end + len_get_end -2
				// because match_end gives the starting position of the match +1
				// and len_get_end gives the length of the match
				// so we need to subtract 2 to get the last char of the match in
				// a zero indexed string
				keep_alive = (line[match_end + len_get_end - 2] == '1');
				// make the starting char of the line as null
				// starting char = match_end - 1
				line[match_end - 1] = 0;
				}

			RequestGet(&line[len_get - 1]);

			req_state = detail::BTT_REQ_HEADER;
			}
			break;

		case detail::BTT_REQ_HEADER:
			{
			if ( ! *line )
				{
				EmitRequest();
				req_state = detail::BTT_REQ_DONE;
				break;
				}

			int len_hdr;
			if ( (len_hdr = re_hdr.MatchPrefix(line)) == -1 )
				{
				ProtocolViolation("BitTorrentTracker: invalid HTTP request header");
				stop_orig = true;
				return false;
				}

			*strchr(line, ':') = 0; // this cannot fail - see regex_hdr
			RequestHeader(line, &line[len_hdr - 1]);
			}
			break;

		case detail::BTT_REQ_DONE:
			if ( *line )
				{
				auto msg = util::fmt("Got post request data: %s\n", line);
				Weird("bittorrent_tracker_data_post_request", msg);
				DeliverWeird(msg, true);
				}
			break;

		default:
			// Make the compiler happy.
			break;
		}

	return true;
	}

void BitTorrentTracker_Analyzer::RequestGet(char* uri)
	{
	req_val_uri = new StringVal(uri);
	}

void BitTorrentTracker_Analyzer::EmitRequest(void)
	{
	ProtocolConfirmation();

	if ( bt_tracker_request )
		EnqueueConnEvent(bt_tracker_request, ConnVal(), IntrusivePtr{AdoptRef{}, req_val_uri},
		                 IntrusivePtr{AdoptRef{}, req_val_headers});

	req_val_uri = nullptr;
	req_val_headers = nullptr;
	}

bool BitTorrentTracker_Analyzer::ParseResponse(char* line)
	{
	static bool initialized = false;
	static RE_Matcher re_stat("^HTTP/[0-9.]* ");
	static RE_Matcher re_hdr("^[^: \t]+:[ ]*");

	if ( ! initialized )
		{
		re_stat.Compile();
		re_hdr.Compile();

		re_stat.MakeCaseInsensitive();
		re_hdr.MakeCaseInsensitive();

		initialized = true;
		}

	switch ( res_state )
		{
		case detail::BTT_RES_STATUS:
			{
			if ( res_allow_blank_line && ! *line )
				{
				// There may be an empty line after the bencoded
				// directory, if this is a keep-alive connection.
				// Ignore it.
				res_allow_blank_line = false;
				break;
				}

			int len_stat;
			if ( (len_stat = re_stat.MatchPrefix(line)) == -1 )
				{
				ProtocolViolation("BitTorrentTracker: invalid HTTP status");
				stop_resp = true;
				return false;
				}

			ResponseStatus(&line[len_stat - 1]);
			res_state = detail::BTT_RES_HEADER;
			}
			break;

		case detail::BTT_RES_HEADER:
			if ( ! *line )
				{
				if ( res_status != 200 )
					{
					if ( bt_tracker_response_not_ok )
						EnqueueConnEvent(bt_tracker_response_not_ok, ConnVal(),
						                 val_mgr->Count(res_status),
						                 IntrusivePtr{AdoptRef{}, res_val_headers});
					res_val_headers = nullptr;
					res_buf_pos = res_buf + res_buf_len;
					res_state = detail::BTT_RES_DONE;
					}
				else
					res_state = detail::BTT_RES_BODY;

				break;
				}

				{
				int len_hdr;
				if ( (len_hdr = re_hdr.MatchPrefix(line)) == -1 )
					{
					ProtocolViolation("BitTorrentTracker: invalid HTTP response header");
					stop_resp = true;
					return false;
					}

				*strchr(line, ':') = 0; // this cannot fail - see regex_hdr
				ResponseHeader(line, &line[len_hdr - 1]);
				}
			break;

		default:
			// Make the compiler happy.
			break;
		}

	return true;
	}

void BitTorrentTracker_Analyzer::ResponseStatus(char* status)
	{
	if ( sscanf(status, FMT_UINT, &res_status) != 1 )
		res_status = 0;
	}

void BitTorrentTracker_Analyzer::ParseHeader(char* name, char* value, bool is_request)
	{
	if ( ! strcasecmp(name, "connection") )
		{
		if ( ! strcasecmp(value, "close") )
			keep_alive = false;
		else
			keep_alive = true;
		}

#ifdef BTTRACKER_STORE_HEADERS
	auto* name_ = new StringVal(name);
	auto* value_ = new StringVal(value);

	(is_request ? req_val_headers : res_val_headers)->Assign(name_, value_);
	Unref(name_);
#endif
	}

void BitTorrentTracker_Analyzer::ResponseBenc(int name_len, char* name, detail::BTT_BencTypes type,
                                              int value_len, char* value)
	{
	if ( name_len == 5 && ! strncmp(name, "peers", 5) )
		{
		for ( char* end = value + value_len; value < end; value += 6 )
			{
			// Note, weirdly/unfortunately AddrVal's take
			// addresses in network order but PortVal's
			// take ports in host order.  BitTorrent specifies
			// that both are in network order here.
			uint32_t ad = extract_uint32((u_char*)value);
			uint16_t pt = ntohs((value[4] << 8) | value[5]);

			auto peer = make_intrusive<RecordVal>(bittorrent_peer);
			peer->Assign(0, make_intrusive<AddrVal>(ad));
			peer->Assign(1, val_mgr->Port(pt, TRANSPORT_TCP));
			res_val_peers->Assign(std::move(peer), nullptr);
			}
		}
	else
		{
		auto name_ = make_intrusive<StringVal>(name_len, name);
		auto benc_value = make_intrusive<RecordVal>(bittorrent_benc_value);
		benc_value->Assign(type, make_intrusive<StringVal>(value_len, value));
		res_val_benc->Assign(std::move(name_), std::move(benc_value));
		}
	}

void BitTorrentTracker_Analyzer::ResponseBenc(int name_len, char* name, detail::BTT_BencTypes type,
                                              bro_int_t value)
	{
	auto benc_value = make_intrusive<RecordVal>(bittorrent_benc_value);
	auto name_ = make_intrusive<StringVal>(name_len, name);

	benc_value->Assign(type, static_cast<int>(value));
	res_val_benc->Assign(std::move(name_), std::move(benc_value));
	}

void BitTorrentTracker_Analyzer::ResponseBody(void)
	{
	switch ( ResponseParseBenc() )
		{
		case 0:
			EmitResponse();
			res_state = detail::BTT_RES_DONE;
			break;

		case -1: // parsing failed
		case -2: // need more data
			break;
		}
	}

int BitTorrentTracker_Analyzer::ResponseParseBenc(void)
	{
#define VIOLATION_IF(expr, msg)                                                                    \
		{                                                                                          \
		if ( expr )                                                                                \
			{                                                                                      \
			ProtocolViolation(msg);                                                                \
			stop_resp = true;                                                                      \
			return -1;                                                                             \
			}                                                                                      \
		}

#define INC_COUNT                                                                                  \
		{                                                                                          \
		unsigned int count = benc_count.back();                                                    \
		benc_count.pop_back();                                                                     \
		benc_count.push_back(count + 1);                                                           \
		}

	for ( unsigned int len = res_buf_len - (res_buf_pos - res_buf); len; --len, ++res_buf_pos )
		{
		switch ( benc_state )
			{
			case detail::BENC_STATE_EMPTY:
				{
				switch ( res_buf_pos[0] )
					{
					case 'd':
						switch ( benc_stack.size() )
							{
							case 0:
								break;
							case 1:
								benc_raw = res_buf_pos;
								benc_raw_type = detail::BENC_TYPE_DIR;
								/* fall through */
							default:
								VIOLATION_IF(benc_stack.back() == 'd' && ! (benc_count.back() % 2),
								             "BitTorrentTracker: directory key is not a string "
								             "but a directory")
								++benc_raw_len;
							}

						benc_stack.push_back('d');
						benc_count.push_back(0);
						break;

					case 'l':
						switch ( benc_stack.size() )
							{
							case 0:
								VIOLATION_IF(1, "BitTorrentTracker: not a bencoded directory "
								                "(first char: l)")
								/* fall through */

							case 1:
								benc_raw = res_buf_pos;
								benc_raw_type = detail::BENC_TYPE_LIST;
								/* fall through */

							default:
								VIOLATION_IF(benc_stack.back() == 'd' && ! (benc_count.back() % 2),
								             "BitTorrentTracker: directory key is not a string "
								             "but a list")
								++benc_raw_len;
							}

						benc_stack.push_back('l');
						benc_count.push_back(0);
						break;

					case 'i':
						VIOLATION_IF(! benc_stack.size(),
						             "BitTorrentTracker: not a bencoded directory (first char: i)")
						VIOLATION_IF(benc_stack.back() == 'd' && ! (benc_count.back() % 2),
						             "BitTorrentTracker: directory key is not a string but an int")

						if ( benc_raw_type != detail::BENC_TYPE_NONE )
							++benc_raw_len;

						benc_state = detail::BENC_STATE_INT1;
						break;

					case 'e':
						VIOLATION_IF(! benc_stack.size(),
						             "BitTorrentTracker: not a bencoded directory (first char: e)")
						VIOLATION_IF(benc_stack.back() == 'd' && benc_count.back() % 2,
						             "BitTorrentTracker: directory has an odd count of members")

						if ( benc_raw_type != detail::BENC_TYPE_NONE )
							++benc_raw_len;

						if ( benc_stack.size() == 2 )
							{ // coming back to level 1
							ResponseBenc(benc_key_len, benc_key, benc_raw_type, benc_raw_len,
							             benc_raw);
							benc_key = nullptr;
							benc_key_len = 0;
							benc_raw = nullptr;
							benc_raw_len = 0;
							benc_raw_type = detail::BENC_TYPE_NONE;
							}

						benc_stack.pop_back();
						benc_count.pop_back();

						if ( benc_stack.size() )
							INC_COUNT
						else
							{ // benc parsing successful
							++res_buf_pos;
							return 0;
							}
						break;

					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						VIOLATION_IF(
							! benc_stack.size(),
							"BitTorrentTracker: not a bencoded directory (first char: [0-9])")

						if ( benc_raw_type != detail::BENC_TYPE_NONE )
							++benc_raw_len;

						benc_strlen = res_buf_pos;
						benc_state = detail::BENC_STATE_STR1;
						break;

					default:
						VIOLATION_IF(1, "BitTorrentTracker: no valid bencoding")
					}
				}
				break;

			case detail::BENC_STATE_INT1:
				benc_int = res_buf_pos;
				if ( res_buf_pos[0] == '-' )
					{
					if ( benc_raw_type != detail::BENC_TYPE_NONE )
						++benc_raw_len;
					benc_state = detail::BENC_STATE_INT2;
					break;
					}

			case detail::BENC_STATE_INT2:
				VIOLATION_IF(res_buf_pos[0] < '0' || res_buf_pos[0] > '9',
				             "BitTorrentTracker: no valid bencoding")

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;

				benc_state = detail::BENC_STATE_INT3;
				break;

			case detail::BENC_STATE_INT3:
				if ( res_buf_pos[0] == 'e' )
					{
					if ( sscanf(benc_int, FMT_INT, &benc_int_val) == 1 )
						{
						if ( benc_stack.size() == 1 )
							{
							ResponseBenc(benc_key_len, benc_key, detail::BENC_TYPE_INT,
							             benc_int_val);
							benc_key = nullptr;
							benc_key_len = 0;
							}
						}
					else
						VIOLATION_IF(1, "BitTorrentTracker: no valid bencoding")

					INC_COUNT
					benc_state = detail::BENC_STATE_EMPTY;
					}

				else
					VIOLATION_IF(res_buf_pos[0] < '0' || res_buf_pos[0] > '9',
					             "BitTorrentTracker: no valid bencoding");

				if ( benc_raw_type != detail::BENC_TYPE_NONE )
					++benc_raw_len;

				break;

			case detail::BENC_STATE_STR1:
				switch ( res_buf_pos[0] )
					{
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						if ( benc_raw_type != detail::BENC_TYPE_NONE )
							++benc_raw_len;
						break;

					case ':':
						VIOLATION_IF(sscanf(benc_strlen, "%u", &benc_str_len) != 1,
						             "BitTorrentTracker: no valid bencoding")

						benc_str_have = 0;
						benc_str = res_buf_pos + 1;

						if ( benc_stack.size() == 1 && ! (benc_count.front() % 2) )
							{
							benc_key = benc_str;
							benc_key_len = benc_str_len;
							}

						if ( benc_raw_type != detail::BENC_TYPE_NONE )
							++benc_raw_len;

						benc_state = detail::BENC_STATE_STR2;
						break;

					default:
						VIOLATION_IF(1, "BitTorrentTracker: no valid bencoding")
					}
				break;

			case detail::BENC_STATE_STR2:
				if ( benc_str_have < benc_str_len )
					{
					unsigned int seek = std::min(len, benc_str_len - benc_str_have);
					benc_str_have += seek;

					if ( benc_raw_type != detail::BENC_TYPE_NONE )
						benc_raw_len += seek;

					res_buf_pos += seek - 1;
					len -= seek - 1;
					}

				if ( benc_str_have == benc_str_len )
					{
					if ( benc_stack.size() == 1 && benc_key && benc_key != benc_str )
						{
						ResponseBenc(benc_key_len, benc_key, detail::BENC_TYPE_STR, benc_str_len,
						             benc_str);
						benc_key_len = 0;
						benc_key = nullptr;
						}

					if ( ! benc_str_len )
						{
						--res_buf_pos;
						++len;
						}

					INC_COUNT
					benc_state = detail::BENC_STATE_EMPTY;
					}
				break;
			}
		}

	return -2; // need more data
	}

void BitTorrentTracker_Analyzer::EmitResponse(void)
	{
	ProtocolConfirmation();

	if ( bt_tracker_response )
		EnqueueConnEvent(bt_tracker_response, ConnVal(), val_mgr->Count(res_status),
		                 IntrusivePtr{AdoptRef{}, res_val_headers},
		                 IntrusivePtr{AdoptRef{}, res_val_peers},
		                 IntrusivePtr{AdoptRef{}, res_val_benc});

	res_val_headers = nullptr;
	res_val_peers = nullptr;
	res_val_benc = nullptr;
	}

	} // namespace zeek::analyzer::bittorrent
