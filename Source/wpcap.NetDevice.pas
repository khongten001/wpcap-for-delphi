unit wpcap.NetDevice;

interface

uses wpcap.Wrapper,wpcap.Conts,wpcap.Types,System.SysUtils,System.Classes;

function GetAdapterList: TStringList;

implementation

/// <summary>
///   Returns a list of the names of all available network interfaces on the system.
/// </summary>
/// <returns>
///   A TStringList object containing the names of all available network interfaces.
/// </returns>
function GetAdapterList: TStringList;
var LAdapterList: Ppcap_if;
    LErrBuffer  : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
begin
  Result := TStringList.Create;
  if pcap_findalldevs(@LAdapterList, LErrBuffer) = -1  then 
    raise Exception.CreateFmt('Error load list interface %S',[String(LErrBuffer)]);

  try
    while Assigned(LAdapterList) do
    begin
      Result.Add(LAdapterList^.name);
      LAdapterList := LAdapterList^.next;
    end;
  finally
    pcap_freealldevs(LAdapterList);
  end;
end;

end.
