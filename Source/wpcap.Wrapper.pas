unit wpcap.Wrapper;

interface


uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  wpcap.Types,WinSock;

  
//*******************************************************************************************************
//*                                                                                                     *
//*                                  WPPCAP.DLL                                                         *
//*                                                                                                     * 
//*******************************************************************************************************


/// <summary>
/// PacketSendPackets is a function that allows you to send a burst of packets
/// through a network adapter. The function accepts the following parameters:
///
/// AdapterObject: Network adapter handle to send packets to.
/// PacketBurst : pointer to a PacketBurst structure that contains the packets to send.
/// sync : When set to TRUE, the function waits for packets to finish sending before returning control to the caller. If set to FALSE,
///
/// the function returns immediately after starting sending packets.
///
/// The function returns TRUE if the operation completed successfully, FALSE otherwise.
/// </summary>
function PacketSendPackets(AdapterObject: THandle; PacketBurst: PPacketBurst; Sync: boolean): boolean;overload; stdcall; external 'wpcap.dll';

/// <summary>
/// The PacketGetNetInfoEx function allows you to get information about the network configuration of a specific adapter.
/// The function accepts the following parameters:
///
/// AdapterObject: Network adapter handle to get information for.
/// lpNetInfo    : A TNetInfoEx structure that is filled with information about the network configuration of the adapter.
///
/// The function returns TRUE if the operation completed successfully, FALSE otherwise.
/// </summary>
function PacketGetNetInfoEx(AdapterObject: THandle; var lpNetInfo: TNetInfoEx): boolean;overload; stdcall; external 'wpcap.dll';

/// <summary>
/// PacketSetModeEx is a function defined in the WinPcap library which is used to set the packet capture mode on a specific network adapter.
/// The function has the following parameters:
///
/// AdapterObject: Network adapter object to set capture mode on.
/// Mode         : Packet capture mode to set on the network adapter. It can take one of the following values:
/// MODE_CAPT    : Capture packets arriving on the physical side of the network adapter.
/// MODE_STAT    : Capture packets passing through the network stack, but not packets arriving on the physical side of the network adapter.
/// MODE_MON     : Monitor mode, used to capture traffic in promiscuous mode.
/// Mode2        : Boolean value that specifies whether the function should return information about the capture mode set on the network adapter. If TRUE, the function will return the requested information in a PPACKET_OID_DATA structure. If it is FALSE, the function will not return any information.
///
/// The function returns a boolean value indicating whether the capture mode setting operation was successful.
/// </summary>
function PacketSetModeEx(AdapterObject: THandle; Mode: ULONG; Mode2: BOOL): BOOL; stdcall;external 'wpcap.dll';

/// <summary>
/// This function allows you to set the packet capture mode for a specific adapter.
/// If mode is set to TRUE, the driver captures packets in promiscuous mode, otherwise in non-promiscuous mode.
///
/// The function returns TRUE if the operation completed successfully, FALSE otherwise.
/// </summary>
function PacketSetMode(AdapterObject: THandle; mode: boolean): boolean; stdcall; external 'wpcap.dll';

/// <summary>
/// Purpose: pcap_next_ex returns the next packet available on the buffer. 
/// If successful, the function returns 1, and pkt_header and pkt_data point to the captured 
/// packet’s libpcap capture information header and the packet, respectively. 
///
/// If not successful,the function returns
/// 0 if the timeout expired,
/// -1 if an error occurred reading the packet, 
/// or -2 
/// if the packet is being read from a saved file and there are no more packets to read.
/// </summary>
function pcap_next_ex(p: Ppcap_t;var pkt_header: PTpcap_pkthdr; pkt_data: PByte): Integer; cdecl; external 'wpcap.dll';

///<summary>
/// Returns a pointer to the error message for the last pcap library error that occurred on the pcap_t descriptor specified.
///</summary>
///<param name="p">
/// A pointer to the pcap_t structure from which to retrieve the error message.
///</param>
///<returns>
/// A pointer to a string containing the error message for the last pcap library error that occurred on the pcap_t descriptor specified.
///</returns>
///<remarks>
/// This function retrieves a pointer to a string containing the error message for the last pcap library error that occurred on the pcap_t descriptor specified. 
// If no error has occurred, the function returns a null pointer.
///</remarks>
function pcap_geterr(p: ppcap_t): PAnsiChar; cdecl; external 'wpcap.dll';  

///<summary>
/// Opens a saved capture file for offline processing.
///</summary>
///<param name="fname">
/// A pointer to a string containing the name of the capture file to open.
///</param>
///<param name="errbuf">
/// A pointer to a buffer that will hold the error message if an error occurs.
///</param>
///<returns>
/// A pointer to a pcap_t structure for the opened capture file, or a null pointer if an error occurred.
///</returns>
///<remarks>
/// This function opens the specified capture file for offline processing and returns a pointer to a pcap_t structure that can be used to read packets from the file. If an error occurs, the function returns a null pointer and the error message is written to the specified error buffer. The caller is responsible for freeing the resources associated with the pcap_t structure using the pcap_close function when processing is complete.
///</remarks>
function pcap_open_offline(const fname: PAnsiChar; errbuf: PAnsiChar): Ppcap_t; cdecl; external 'wpcap.dll';

///<summary>
/// Closes the specified pcap_t descriptor.
///</summary>
///<param name="p">
/// A pointer to the pcap_t descriptor to close.
///</param>
///<remarks>
/// This procedure closes the specified pcap_t descriptor. 
/// If the descriptor is currently capturing packets, the capture process will be terminated.
///</remarks>
procedure pcap_close(p: Ppcap_t); cdecl; external 'wpcap.dll';


///<summary>
/// Sets a filter for the captured packets using an instance of WinPcap.
///</summary>
/// <param name="AdapterObject">The handle of the instance of WinPcap.</param>
/// <param name="fp">The input must be a pointer to the bpf_program structure that contains the compiled filter.</param>
/// <returns>A boolean value that indicates whether the operation was successful.</returns>
function pcap_setfilter(AdapterObject: Ppcap_t; fp: PBPF_program): LongInt; stdcall; external 'wpcap.dll';

/// <summary>
/// Compile a BPF filter expression into a BPF filter program.
/// </summary>
/// <param name="p">A pointer to a pcap_t structure, which has been created by a call to pcap_open_offline() or pcap_create().</param>
/// <param name="fp">A pointer to a BPF_program struct where the compiled filter will be stored.</param>
/// <param name="str">A string containing the BPF filter expression.</param>
/// <param name="optimize">An integer indicating whether the compiled program should be optimized for speed or size. 
/// Use 0 for no optimization, 1 for optimizing for speed, or 2 for optimizing for size.</param>
/// <param name="netmask">The network mask to apply to the filter expression.</param>
/// <returns>An integer indicating whether the compilation was successful (0) or not (-1).</returns>
function pcap_compile(p: Ppcap_t; fp: PBPF_program; str: PAnsiChar; optimize: Integer; netmask: UInt32): Integer; cdecl; external 'wpcap.dll';

/// <summary>
/// Opens a new pcap_t data link to be used as a target to write packets into, and returns a handle to the pcap_t.
/// </summary>
/// <param name="Linktype">The link layer type for packets that will be written to the pcap_t.</param>
/// <param name="Snaplen">The maximum number of bytes to be captured for each packet.</param>
/// <returns>A pointer to the pcap_t handle, or nil if an error occurs.</returns>
function pcap_open_dead(Linktype: Integer; Snaplen: Integer): ppcap_t; cdecl; external 'wpcap.dll';

///<summary>
/// Opens a dump file for writing packets. This function creates a new <c>pcap_dumper_t</c> for the specified <c>pcap_t</c> and returns a pointer to the <c>pcap_dumper_t</c>.
///</summary>
///<param name="p">A pointer to a <c>pcap_t</c> that is obtained by calling <c>pcap_open_live</c>.</param>
///<param name="fname">The name of the file to which the packets will be written.</param>
///<returns>A pointer to a <c>pcap_dumper_t</c> that will be used to write the packets to the file.</returns>
///<remarks>Once the file has been opened, packets can be written to the file using the <c>pcap_dump</c> function.</remarks>
function pcap_dump_open(p: Ppcap_t; const fname: PAnsiChar): ppcap_dumper_t; cdecl; external 'wpcap.dll'

///<summary>
/// This function writes the raw packet data to the file that was opened using the
/// `pcap_dump_open()` function.
///</summary>
///<param name="dumper">A pointer to the `pcap_dumper_t` structure that was returned
/// by `pcap_dump_open()`.</param>
///<param name="h">A pointer to a `pkt_header` structure that describes the packet.
///</param>
///<param name="sp">A pointer to the packet data.</param>
///<returns>The function returns 0 on success, and -1 on error.</returns>
///<remarks>
/// This function writes the raw packet data to the file that was opened using the
/// `pcap_dump_open()` function. The packet is described by the `pkt_header` structure
/// pointed to by `h`, and the packet data is pointed to by `sp`.
///</remarks>
function pcap_dump(dumper: ppcap_dumper_t; const h: PTpcap_pkthdr; const sp: PByte): Integer; cdecl; external 'wpcap.dll';

/// <summary>
/// Closes the output dump file associated with the given pcap_dumper_t structure.
/// </summary>
/// <param name="dumper">The pcap_dumper_t structure to close.</param>
/// <returns>Returns 0 on success or -1 on failure.</returns>
function pcap_dump_close(dumper: ppcap_dumper_t): Longint; cdecl; external 'wpcap.dll';

/// <summary>
///   Returns a linked list of all network interfaces available on the system.
/// </summary>
/// <param name="alldevsp">
///   Pointer to a PTCartInterface pointer that will be set to point to the first element in the linked list.
/// </param>
/// <param name="errbuf">
///   Pointer to a buffer that will be filled with an error message if the function fails.
/// </param>
/// <returns>
///   0 on success, or a negative value on failure. The error message will be stored in the buffer pointed to by `errbuf`.
/// </returns>
function pcap_findalldevs(alldevsp: PTCartInterface; errbuf: PAnsiChar): Integer; cdecl; external 'wpcap.dll';

/// <summary>
///   Frees the memory associated with the linked list of network interfaces returned by pcap_findalldevs.
/// </summary>
/// <param name="alldevsp">
///   Pointer to the first element in the linked list of network interfaces returned by pcap_findalldevs.
/// </param>
procedure pcap_freealldevs(alldevsp: PTCartInterface); cdecl; external 'wpcap.dll';

///<summary>
/// Opens a network interface for live packet capture using WinPcap.
///</summary>
/// <param name="device">
/// The name of the network interface device to open for packet capture.
/// </param>
/// <param name="snaplen">
/// The maximum number of bytes to capture for each packet.
/// </param>
/// <param name="promisc">
/// A flag that indicates whether to put the interface into promiscuous mode.
/// </param>
/// <param name="to_ms">
/// The read timeout, in milliseconds.
/// </param>
/// <param name="errbuf">
/// A buffer to hold error messages if the function call fails.
/// </param>
/// <returns>
/// A pointer to the `pcap_t` structure that represents the opened interface,
/// or `nil` if the function call fails.
/// </returns>
function pcap_open_live(const device: PAnsiChar; snaplen: Integer;promisc: Integer; to_ms: Integer; errbuf: PAnsiChar): Ppcap_t; cdecl;external 'wpcap.dll';  

///<summary>
/// Captures a specified number of packets and calls a user-provided
/// callback function for each packet.
///</summary>
/// <param name="pcap">
/// A pointer to the `pcap_t` structure that represents the network interface
/// to capture packets from.
/// </param>
/// <param name="cnt">
/// The number of packets to capture. A negative value means to capture
/// packets indefinitely.
/// </param>
/// <param name="callback">
/// A pointer to the user-provided callback function that will be called
/// for each packet.
/// </param>
/// <param name="user">
/// A pointer to user-defined data that will be passed to the callback function
/// for each packet.
/// </param>
/// <returns>
/// The number of packets that were captured, or -1 if an error occurred.
/// </returns>
function pcap_loop(pcap: Ppcap_t; cnt: Integer;aCallback: pcap_handler; user: PansiChar): Integer; cdecl; external 'wpcap.dll';

/// <summary>
/// Break a packet capture loop.
///
/// This function is used to break out of a packet capture loop created with
/// pcap_loop or pcap_dispatch.
/// </summary>
/// <param name="p">A pointer to a pcap_t structure returned by pcap_open_live or pcap_open_offline.</param>
function pcap_breakloop(p: Ppcap_t): Integer;cdecl; external 'wpcap.dll';

/// <summary>
///   Sets the direction of the packets to be captured.
/// </summary>
/// <remarks>
///   This function sets the direction of the packets to be captured. Only packets that have the specified direction relative to the machine capturing the packets will be captured. If the direction parameter is set to PCAP_D_INOUT, both incoming and outgoing packets will be captured. This function should be called after the pcap_open_live() function.
/// </remarks>
/// <param name="p">A pointer to the pcap_t structure that was returned by pcap_open_live().</param>
/// <param name="direction">The direction of the packets to capture (either PCAP_D_IN, PCAP_D_OUT, PCAP_D_INOUT).</param>
/// <returns>Returns 0 on success or a negative value on failure.</returns>
function pcap_setdirection(p: ppcap_t; direction: TPcapDirection): Integer; cdecl; external 'wpcap.dll';

///  <summary>
///    Looks up the network address and netmask for the specified network interface
///  </summary>
///  <param name="device">
///    A null-terminated string that specifies the network device to look up, such as "eth0" or "wlan0".
///  </param>
///  <param name="netp">
///    A pointer to a network address that will be set to the network address of the network interface.
///  </param>
///  <param name="maskp">
///    A pointer to a network mask that will be set to the netmask of the network interface.
///  </param>
///  <param name="errbuf">
///    A buffer that will be filled with an error message if the function fails.
///  </param>
///  <returns>
///    0 if successful, or -1 on failure.
///  </returns>
function pcap_lookupnet(device: PAnsiChar; var netp, maskp: bpf_u_int32; errbuf: PAnsiChar): Integer; cdecl;external 'wpcap.dll';

/// <summary>
/// Create a source string that identifies a network interface to capture from, using various parameters.
/// </summary>
/// <param name="source">The resulting source string. Must be a pointer to a buffer that is at least "PCAP_BUF_SIZE" bytes long.</param>
/// <param name="type">The type of the source. This should be one of the "PCAP_SRC_*" constants defined in "pcap.h".</param>
/// <param name="name">The name of the network device to capture from, or a URL specifying the remote device to capture from.</param>
/// <param name="config">A string containing additional configuration parameters, or NULL if none are needed.</param>
/// <param name="errbuf">A buffer to hold error messages in case of failure. Should be at least "PCAP_ERRBUF_SIZE" bytes long.</param>
/// <returns>Returns 0 on success, or -1 on failure.</returns>
function pcap_createsrcstr(source: PAnsiChar; type_: PAnsiChar; const name: PAnsiChar; const config: PAnsiChar; errbuf: PAnsiChar): Integer; cdecl;external 'wpcap.dll';

/// <summary>
/// Get the link-layer header type of the pcap_t session.
/// </summary>
/// <param name="p">A pointer to the pcap_t session.</param>
/// <returns>Returns the link-layer header type of the session, as one of the "DLT_*" constants defined in "pcap.h". Returns "PCAP_ERROR" if an error occurs.</returns>
function pcap_datalink(p: Ppcap_t): Integer; cdecl; external 'wpcap.dll';

///  <summary>
///  Looks up the default network device name.
///  </summary>
///  <returns>
///  A pointer to a string containing the name of the first device suitable for capturing network traffic, or NULL if an error occurred. 
///  </returns>
///  <remarks>
///  You can use this function to determine the default device to use for capturing network traffic.
///  </remarks>
function pcap_lookupdev(errbuf: PAnsiChar): PAnsiChar; cdecl; external 'wpcap.dll';



//******************************************************************************************************
//*                                                                                                     *
//*                                  PACKET.DLL                                                         *
//*                                                                                                     * 
//*******************************************************************************************************

///<summary>
/// Returns the version string of the Packet library.
///</summary>
///<returns>
/// A pointer to a string containing the version of the Packet library.
///</returns>
///<remarks>
/// This function returns a pointer to a string containing the version of the Packet library in use.
///</remarks>
function PacketGetVersion: PAnsiChar; stdcall; external 'Packet.dll';

///<summary>
/// Returns the version of the NPF driver.
///</summary>
///<returns>
/// The version number of the NPF driver.
///</returns>
///<remarks>
/// This function returns the version number of the NPF driver in use.
///</remarks>
function PacketGetDriverVersion: ULONG; stdcall; external 'Packet.dll';


implementation



end.
