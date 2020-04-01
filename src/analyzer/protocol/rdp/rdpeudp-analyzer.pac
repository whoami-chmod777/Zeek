refine connection RDPEUDP_Conn += {
	%member{
		enum RDPEUDP_STATE {
		        NEED_SYN	= 0x1,
		        NEED_SYNACK	= 0x2,
			NED_ACK		= 0x3,
		        ESTABLISHED	= 0x4,
		};
		uint8 state_ = NEED_SYN;
		bool client_rdpeudp2_ = false;
		bool server_rdpeudp2_ = false;
	%}
	function get_state(): uint8
	%{
		return state_;
	%}

        function proc_rdpeudp_syn(is_orig: bool, uFlags: uint16, snSourceAck: uint32): bool
	%{
		if (!is_orig) {
			return false;
		}
                if ((uFlags & 0x01) == 0) {
                        return false;
                }
		if (snSourceAck != 0xffffffff) {
			return false;
		}
		if (uFlags >= 0x1000) {
			client_rdpeudp2_ = true;
		}
                BifEvent::generate_rdpeudp_syn(bro_analyzer(), bro_analyzer()->Conn());
		state_ = NEED_SYNACK;
                return true;
	%}

        function proc_rdpeudp_synack(is_orig: bool, uFlags: uint16): bool
	%{
		if (is_orig) {
			return false;
		}

		if ((uFlags & 0x05) == 0) {
			return false;
		}
                BifEvent::generate_rdpeudp_synack(bro_analyzer(), bro_analyzer()->Conn());
		bro_analyzer()->ProtocolConfirmation();
		state_ = NEED_ACK;
		if (uFlags >= 0x1000) {
			server_rdpeudp2_ = true;
		}
                return true;
	%}

        function proc_rdpeudp_ack(is_orig: bool, data: bytestring): bool
	%{
        	BifEvent::generate_rdpeudp_established(bro_analyzer(), bro_analyzer()->Conn());
		state_ = ESTABLISHED;
		if ( rdpeudp_data )
			BifEvent::generate_rdpeudp_data(bro_analyzer(),
							bro_analyzer()->Conn(),
							is_orig,
							new StringVal(data.length(), (const char*) data.data())
			);
                return true;
	%}
};
