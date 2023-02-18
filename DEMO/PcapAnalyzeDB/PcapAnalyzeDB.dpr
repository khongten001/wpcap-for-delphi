program PcapAnalyzeDB;

uses
  Vcl.Forms,
  UnMain in 'UnMain.pas' {FormMain},
  wpcap.Pcap.SQLite in '..\..\Source\wpcap.Pcap.SQLite.pas',
  wpcap.Conts in '..\..\Source\wpcap.Conts.pas',
  wpcap.IOUtils in '..\..\Source\wpcap.IOUtils.pas',
  wpcap.Pcap in '..\..\Source\wpcap.Pcap.pas',
  wpcap.Protocol in '..\..\Source\wpcap.Protocol.pas',
  wpcap.StrUtils in '..\..\Source\wpcap.StrUtils.pas',
  wpcap.Types in '..\..\Source\wpcap.Types.pas',
  wpcap.Wrapper in '..\..\Source\wpcap.Wrapper.pas',
  wpcap.DB.SQLite in '..\..\Source\wpcap.DB.SQLite.pas',
  wpcap.Filter in '..\..\Source\wpcap.Filter.pas',
  wpcap.DB.Base in '..\..\Source\wpcap.DB.Base.pas',
  UnFormRecording in 'UnFormRecording.pas' {FormRecording},
  wpcap.NetDevice in '..\..\Source\wpcap.NetDevice.pas',
  wpcap.Graphics in '..\..\Source\wpcap.Graphics.pas',
  wpcap.Protocol.DNS in '..\..\Source\Protocols\wpcap.Protocol.DNS.pas',
  wpcap.Protocol.UDP in '..\..\Source\Protocols\wpcap.Protocol.UDP.pas',
  wpcap.Protocol.L2TP in '..\..\Source\Protocols\wpcap.Protocol.L2TP.pas',
  wpcap.Protocol.NTP in '..\..\Source\Protocols\wpcap.Protocol.NTP.pas',
  wpcap.Protocol.Base in '..\..\Source\wpcap.Protocol.Base.pas',
  wpcap.Protocol.MDNS in '..\..\Source\Protocols\wpcap.Protocol.MDNS.pas',
  wpcap.Protocol.LLMNR in '..\..\Source\Protocols\wpcap.Protocol.LLMNR.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
