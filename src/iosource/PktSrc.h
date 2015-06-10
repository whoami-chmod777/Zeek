// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PKTSRC_H
#define IOSOURCE_PKTSRC_PKTSRC_H

#include "IOSource.h"
#include "BPF_Program.h"
#include "Dict.h"

declare(PDict,BPF_Program);

namespace iosource {

/**
 * Base class for packet sources.
 */
class PktSrc : public IOSource {
public:
	static const int NETMASK_UNKNOWN = 0xffffffff;

	/**
	 * Struct for returning statistics on a packet source.
	 */
	struct Stats {
		/**
		 * Packets received by source after filtering (w/o drops).
		 */
		unsigned int received;

		/**
		 * Packets dropped by source.
		 */
		unsigned int dropped;	// pkts dropped

		/**
		 * Total number of packets on link before filtering.
		 * Optional, can be left unset if not available.
		 */
		unsigned int link;

		/**
		  * Bytes received by source after filtering (w/o drops).
		*/
		uint64 bytes_received;

		Stats()	{ received = dropped = link = bytes_received = 0; }
	};

	/**
	 * Structure describing ethernet parameters
	 */
	struct EthernetParameters {
		int vlans[2];
		const u_char* source_mac;
		const u_char* destination_mac;

		EthernetParameters() { Clear(); }

		void Clear()
			{
			vlans[0] = vlans[1] = -1;
			source_mac = destination_mac = 0;
			}

		bool OuterVLAN(int *vlan)
			{
			if (vlans[0] == -1)
				return false;

			*vlan = vlans[0];
			return true;
			}

		bool InnerVLAN(int *vlan)
			{
			if (vlans[1] == -1)
				return false;

			*vlan = vlans[1];
			return true;
			}


		bool SourceMAC(char *buf, size_t bufsize) { return MACAddressStr(source_mac, buf, bufsize); }

		bool DestinationMAC(char *buf, size_t bufsize) { return MACAddressStr(destination_mac, buf, bufsize); }

		bool MACAddressStr(const u_char *mac, char *buf, size_t bufsize)
			{
			if ( ! mac )
				return false;

			int n = snprintf(buf, bufsize, "%02x%02x%02x%02x%02x%02x", 
					mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

			return (n == 12);
			}
	};

	/**
	 * Structure describing a packet.
	 */
	struct Packet {
		/**
		 *  Time associated with the packet.
		 */
		double ts;

		/**
		 *  The pcap header associated with the packet.
		 */
		const struct ::pcap_pkthdr* hdr;

		/**
		 * The full content of the packet.
		 */
		const u_char* data;

		EthernetParameters ethernet_parameters;

		uint32 TotalLen(bool captured=true) const { return captured?hdr->caplen:hdr->len; }
	};

	/**
	 * Constructor.
	 */
	PktSrc();

	/**
	 * Destructor.
	 */
	virtual ~PktSrc();

	/**
	 * Returns the path associated with the source. This is the interface
	 * name for live source, and a filename for offline sources.
	 */
	const std::string& Path() const;

	/**
	 * Returns true if this is a live source.
	 */
	bool IsLive() const;

	/**
	 * Returns the link type of the source.
	 */
	int LinkType() const;

	/**
	 * Returns the netmask associated with the source, or \c
	 * NETMASK_UNKNOWN if unknown.
	 */
	uint32 Netmask() const;

	/**
	 * Returns true if the source has flagged an error.
	 */
	bool IsError() const;

	/**
	 * If the source encountered an error, returns a corresponding error
	 * message. Returns an empty string otherwise.
	 */
	const char* ErrorMsg() const;

	/**
	 * Returns the size of the link-layer header for this source.
	 */
	int HdrSize() const;

	/**
	 * Returns the snap length for this source.
	 */
	int SnapLen() const;

	/**
	 * In pseudo-realtime mode, returns the logical timestamp of the
	 * current packet. Undefined if not running pseudo-realtime mode.
	 */
	double CurrentPacketTimestamp();

	/**
	 * In pseudo-realtime mode, returns the wall clock time associated
	 * with current packet. Undefined if not running pseudo-realtime
	 * mode.
	 */
	double CurrentPacketWallClock();

	/**
	 * Signals packet source that processing is going to be continued
	 * after previous suspension.
	 */
	void ContinueAfterSuspend();

	/**
	 * Precompiles a BPF filter and associates the given index with it.
	 * The compiled filter will be then available via \a GetBPFFilter().
	 *
	 * This is primarily a helper for packet source implementation that
	 * want to apply BPF filtering to their packets.
	 *
	 * @param index The index to associate with the filter.
	 *
	 * @param BPF filter The filter string to precompile.
	 *
	 * @return True on success, false if a problem occurred.
	 */
	bool PrecompileBPFFilter(int index, const std::string& filter);

	/**
	 * Returns the precompiled BPF filter associated with a given index,
	 * if any, as compiled by \a PrecompileBPFFilter().
	 *
	 * This is primarily a helper for packet source implementation that
	 * want to apply BPF filtering to their packets.
	 *
	 * @return The BPF filter associated, or null if none has been
	 * (successfully) compiled.
	 */
	BPF_Program* GetBPFFilter(int index);

	/**
	 * Applies a precompiled BPF filter to a packet. This will close the
	 * source with an error message if no filter with that index has been
	 * compiled.
	 *
	 * This is primarily a helper for packet source implementation that
	 * want to apply BPF filtering to their packets.
	 *
	 * @param index The index of the filter to apply.
	 *
	 * @param p The packet to apply the filter to.
	 *
	 * @return True if it maches. 	 */
	bool ApplyBPFFilter(int index, const Packet *p);

	/**
	 * Returns the packet currently being processed, if available.
	 *
	 * @return A pointer to the current packet, if available, or NULL if not.
	 */
	const Packet *GetCurrentPacket();

	// PacketSource interace for derived classes to override.

	/**
	 * Precompiles a filter and associates a given index with it. The
	 * filter syntax is defined by the packet source's implenentation.
	 *
	 * Derived classes must implement this to implement their filtering.
	 * If they want to use BPF but don't support it natively, they can
	 * call the corresponding helper method provided by \a PktSrc.
	 *
	 * @param index The index to associate with the filter
	 *
	 * @param filter The filter string to precompile.
	 *
	 * @return True on success, false if a problem occurred or filtering
	 * is not supported.
	 */
	virtual bool PrecompileFilter(int index, const std::string& filter) = 0;

	/**
	 * Activates a precompiled filter with the given index.
	 *
	 * Derived classes must implement this to implement their filtering.
	 * If they want to use BPF but don't support it natively, they can
	 * call the corresponding helper method provided by \a PktSrc.
	 *
	 * @param index The index of the filter to activate.
	 *
	 * @return True on success, false if a problem occurred or the
	 * filtering is not supported.
	 */
	virtual bool SetFilter(int index) = 0;

	/**
	 * Returns current statistics about the source.
	 *
	 * Derived classes must implement this method.
	 *
	 * @param stats A statistics structure that the method fill out.
	 */
	virtual void Statistics(Stats* stats) = 0;

	/**
	 * Helper method to return the header size for a given link tyoe.
	 *
	 * @param link_type The link tyoe.
	 *
	 * @return The header size in bytes.
	 */
	static int GetLinkHeaderSize(int link_type);

protected:
	friend class Manager;

	// Methods to use by derived classes.

	/**
	 * Structure to pass back information about the packet source to the
	 * base class. Derived class pass an instance of this to \a Opened().
	 */
	struct Properties {
		/**
		 * The path associated with the source. This is the interface
		 * name for live source, and a filename for offline sources.
		 */
		std::string path;

		/**
		 * A file descriptor suitable to use with \a select() for
		 * determining if there's input available from this source.
		 */
		int selectable_fd;

		/**
		 * The link type for packets from this source.
		 */
		int link_type;

		/**
		 * The size of the link-layer header for packets from this
		 * source. \a GetLinkHeaderSize() may be used to derive this
		 * value.
		 */
		int hdr_size;

		/**
		 * Returns the netmask associated with the source, or \c
		 * NETMASK_UNKNOWN if unknown.
		 */
		uint32 netmask;

		/**
		 * True if the source is reading live inout, false for
		 * working offline.
		 */
		bool is_live;

		Properties();
	};

	/**
	 * Called from the implementations of \a Open() to signal that the
	 * source has been successully opened.
	 *
	 * @param props A properties instance describing the now open source.
	 */
	void Opened(const Properties& props);

	/**
	 * Called from the implementations of \a Close() to signal that the
	 * source has been closed.
	 */
	void Closed();

	/**
	 * Can be called from derived classes to send an informational
	 * message to the user.
	 *
	 * @param msg The message to pass on.
	 */
	void Info(const std::string& msg);

	/**
	 * Can be called from derived classes to flag send an error.
	 *
	 * @param msg The message going with the error.
	 */
	void Error(const std::string& msg);

	/**
	 * Can be called from derived classes to flah a "weird" situation.
	 *
	 * @param msg The message to pass on.
	 *
	 * @param pkt The packet associated with the weird, or null if none.
	 */
	void Weird(const std::string& msg, const Packet* pkt);

	/**
	 * Can be called from derived classes to flag an internal error,
	 * which will abort execution.
	 *
	 * @param msg The message to pass on.
	 */
	void InternalError(const std::string& msg);

	// PktSrc interface for derived classes to implement.

	/**
	 * Called by the manager system to open the source.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Opened(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Open() = 0;

	/**
	 * Called by the manager system to close the source.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Closed(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Close() = 0;

	/**
	 * Provides the next packet from the source.
	 *
	 * @param pkt The packet structure to fill in with the packet's
	 * information. The callee keep ownership of the data but must
	 * guaranetee that it stays available at least until \a
	 * DoneWithPacket() is called.  It is guaranteed that no two calls to
	 * this method will hapen with \a DoneWithPacket() in between.
	 *
	 * @return True if a packet is available and *pkt* filled in. False
	 * if not packet is available or an error occured (which must be
	 * flageed via Error()).
	 */
	virtual bool ExtractNextPacket(Packet* pkt) = 0;

	/**
	 * Signals that the data of previously extracted packet will no
	 * longer be needed.
	 */
	virtual void DoneWithPacket() = 0;

private:
	// Checks if the current packet has a pseudo-time <= current_time. If
	// yes, returns pseudo-time, otherwise 0.
	double CheckPseudoTime();

	// Internal helper for ExtractNextPacket().
	bool ExtractNextPacketInternal();

	// IOSource interface implementation.
	virtual void Init();
	virtual void Done();
	virtual void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	                    iosource::FD_Set* except);
	virtual double NextTimestamp(double* local_network_time);
	virtual void Process();
	virtual const char* Tag();

	Properties props;

	bool have_packet;
	Packet current_packet;

	// For BPF filtering support.
	PDict(BPF_Program) filters;

	// Only set in pseudo-realtime mode.
	double first_timestamp;
	double first_wallclock;
	double current_wallclock;
	double current_pseudo;
	double next_sync_point; // For trace synchronziation in pseudo-realtime

	std::string errbuf;
};

}

#endif
