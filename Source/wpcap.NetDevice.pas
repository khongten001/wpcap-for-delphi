unit wpcap.NetDevice;

interface

uses
  wpcap.Wrapper, wpcap.Conts, wpcap.Types, System.SysUtils, System.Classes,
  System.Generics.Collections,WinSock;

type

  TCartInterfaceInternal = record
    name        : String;      // Name of the network interface card.
    description : String;      // Description of the network interface card.
    addresses   : String;     // Pointer to the list of IP addresses associated with the network interface card.
    flags       : bpf_u_int32;    // Flags that contain information about the network interface card.
  end; 
  
  TListCardInterface = class(TList<TCartInterfaceInternal>);  


function GetAdapterList: TListCardInterface;

implementation

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
    LInAddr      : TInAddr; 
begin
  Result := TListCardInterface.Create;
  if pcap_findalldevs(@LAdapterList, LErrBuffer) = -1  then 
    raise Exception.CreateFmt('Error load list interface %S',[String(LErrBuffer)]);

  try
    while Assigned(LAdapterList) do
    begin
      LCard.name        := LAdapterList^.name;
      LCard.description := LAdapterList^.description;
      LCard.flags       := LAdapterList^.flags;
      
      // get ip and mask
      if pcap_lookupnet(LAdapterList^.name, Lnetp, Lmaskp, LErrBuffer) = -1 then
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
