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
  wpcap.NetDevice in '..\..\Source\wpcap.NetDevice.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
