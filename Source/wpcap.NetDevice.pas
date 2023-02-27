unit wpcap.NetDevice;

interface

uses
  wpcap.Wrapper, wpcap.Conts, wpcap.Types, System.SysUtils, System.Classes,
  System.Generics.Collections,WinSock,WinApi.Windows,Winapi.IpHlpApi,Winapi.IpTypes;

type

  TCartInterfaceInternal = record
    name        : String;     
    GUID        : String;       // Name of the network interface card. format Device\{GUID}
    description : String;       // Description of the network interface card.
    addresses   : String;       // Pointer to the list of IP addresses associated with the network interface card.
    flags       : bpf_u_int32;  // Flags that contain information about the network interface card.
  end; 
  
  TListCardInterface = class(TList<TCartInterfaceInternal>);  

/// <summary>
/// Extracts the simplified name of a network interface from its GUID.
/// </summary>
/// <param name="aGuid">The GUID of the network interface, in the format "\\Device\\NPF_{GUID}".</param>
/// <returns>The simplified name of the network interface, or an empty string if the GUID is invalid.</returns>
function GetAdapterNameFromGUID(const aGUID: String): string;
  
/// <summary>
/// Retrieves a list of available network adapters.
/// </summary>
/// <remarks>
/// The returned list should be freed by the caller when it is no longer needed.
/// </remarks>
function GetAdapterList: TListCardInterface;

implementation


function GetAdapterNameFromGUID(const aGUID: String): string;
var LErrBuf     : array [0..PCAP_ERRBUF_SIZE - 1] of AnsiChar;
    LAdapterName: PAnsiChar;
begin
  // Use pcap_lookupdev to resolve the adapter name from the GUID
  LAdapterName := pcap_lookupdev(LErrBuf);
  if LAdapterName = nil then
    raise Exception.CreateFmt('Error resolving adapter name from GUID %s: %s', [aGUID, LErrBuf]);

  Result := string(LAdapterName);
end;

/// <summary>
///   Returns a list of the names of all available network interfaces on the system.
/// </summary>
/// <returns>
///   A TListCardInterface object containing the info of all available network interfaces.
/// </returns>
function GetAdapterList: TListCardInterface;
var LAdapterList: PTCartInterface;
    LErrBuffer  : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LCard       : TCartInterfaceInternal;
    Lnetp       : bpf_u_int32;
    Lmaskp      : bpf_u_int32;   
    LInAddr     : TInAddr; 
begin
  Result := TListCardInterface.Create;
  if pcap_findalldevs(@LAdapterList, LErrBuffer) = -1  then 
    raise Exception.CreateFmt('Error load list interface %S',[String(LErrBuffer)]);

  try
    while Assigned(LAdapterList) do
    begin
      LCard.GUID        := LAdapterList^.GUID;
      LCard.description := LAdapterList^.description;
      LCard.flags       := LAdapterList^.flags;
      LCard.name        := GetAdapterNameFromGUID(LAdapterList^.GUID);
      
      // get ip and mask
      if pcap_lookupnet(LAdapterList^.GUID, Lnetp, Lmaskp, LErrBuffer) = -1 then
        raise Exception.CreateFmt('Error load pcap_lookupnet interface %S',[String(LErrBuffer)]);
      LInAddr.s_addr  := Lnetp;
      LCard.addresses := String(inet_ntoa(LInAddr));
              
      Result.Add(LCard);
      LAdapterList := LAdapterList^.next;
    end;
  finally
    pcap_freealldevs(LAdapterList);
  end;
end;

end.
