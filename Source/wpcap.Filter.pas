unit wpcap.Filter;

interface

uses wpcap.Wrapper,wpcap.Types,wpcap.Conts,WinSock;

/// <summary>
///   Validates a given WinPcap filter expression string to ensure its syntax is correct.
/// </summary>
/// <param name="aFilterExpression">
///   A string containing the WinPcap filter expression to validate.
/// </param>
/// <returns>
///   Returns True if the filter expression is valid, False otherwise.
/// </returns>
function ValidateWinPCAPFilterExpression(const aFilterExpression: string): Boolean;

/// <summary>
/// This is a static class function that checks a wpcap filter. It takes four parameters: a handle to the pcap file, the name of the file, the filter to check, and a callback function to handle errors.
/// </summary>
/// <param name="aHandlePcap">A handle to the pcap file.</param>
/// <param name="aFileName">The name of the pcap file.</param>
/// <param name="aFilter">The filter to check.</param>
/// <param name="aPCAPCallBackError">A callback function to handle errors.</param>
/// <returns>True if the filter is valid; otherwise, False.</returns>
function CheckWPcapFilter(aHandlePcap: Ppcap_t; const aFileName, aFilter,aIP: string; aPCAPCallBackError: TPCAPCallBackError): Boolean;


implementation

function ValidateWinPCAPFilterExpression(const aFilterExpression: string): Boolean;
var LFilterHandle : Ppcap_t;
    LNetMask      : bpf_u_int32;        
    LFilterCode   : BPF_program;      
begin
  Result        := False;
  LFilterHandle := pcap_open_dead(DLT_EN10MB, MAX_PACKET_SIZE);
  if (LFilterHandle = nil) then Exit;
  try
    Result := pcap_compile(LFilterHandle, @LFilterCode, PAnsiChar(AnsiString(aFilterExpression)), 1, LNetMask) > -1;
  finally
    pcap_close(LFilterHandle);
  end;
end;

function CheckWPcapFilter(aHandlePcap : Ppcap_t;const aFileName,aFilter,aIP: string;aPCAPCallBackError:TPCAPCallBackError) : Boolean;
var LFilterCode : BPF_program;  
begin
  Result := False;
  {Filter}
 // if Not aFilter.Trim.IsEmpty then
  begin
    if pcap_compile(aHandlePcap, @LFilterCode, PAnsiChar(AnsiString(aFilter)), 1, inet_addr(PAnsiChar(AnsiString(aIP)))) <> 0 then
    begin
      aPCAPCallBackError(aFileName,string(pcap_geterr(aHandlePcap)));            
      Exit;
    end;
      
    if pcap_setfilter(aHandlePcap,@LFilterCode) <>0 then
    begin
      aPCAPCallBackError(aFileName,string(pcap_geterr(aHandlePcap)));
      Exit;
    end;
  end;
  Result := True;
end;


end.
