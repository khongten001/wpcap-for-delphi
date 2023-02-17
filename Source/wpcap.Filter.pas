unit wpcap.Filter;

interface

uses wpcap.Wrapper,wpcap.Types,wpcap.Conts;

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


end.
