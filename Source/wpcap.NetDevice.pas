unit wpcap.NetDevice;

interface

uses
  wpcap.Wrapper, wpcap.Conts, wpcap.Types, System.SysUtils, System.Classes,System.Win.Registry,
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
CONST REG_PATH = 'SYSTEM\ControlSet001\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\%S\Connection';
var LReg : TRegistry;
    LKey : string;
begin
  Result := aGUID;
  Try
    LReg := TRegistry.Create;
    try
      LReg.RootKey := HKEY_LOCAL_MACHINE;
      LKey := Format(REG_PATH,[aGUID.Split(['_'])[1]]); 
      if LReg.OpenKeyReadOnly(LKey) then
      begin     
        Try
          Result := LReg.ReadString('Name');
        Except 
          ;
        End;
        LReg.CloseKey;
      end;
    finally
      FreeAndNil(LReg);
    end;
  Except

  End;
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
