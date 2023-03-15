unit UnFormPlayerWave;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.MPlayer,MMSystem, Vcl.ExtCtrls;

type

  TWaveHeaderNoData = packed record             
    ChunkID: array [0..3] of AnsiChar;    // Contiene sempre la stringa 'RIFF'
    ChunkSize: Cardinal;                   // Dimensione totale del file in byte - 8
    Format: array [0..3] of AnsiChar;      // Contiene sempre la stringa 'WAVE'
    Subchunk1ID: array [0..3] of AnsiChar; // Contiene sempre la stringa 'fmt '
    Subchunk1Size: Cardinal;               // Dimensione del chunk fmt, fisso a 16
    AudioFormat: Word;                     // Formato audio (1 = PCM)
    NumChannels: Word;                     // Numero di canali (1 = mono, 2 = stereo)
    SampleRate: Cardinal;                  // Frequenza di campionamento (es. 44100 Hz)
    ByteRate: Cardinal;                    // Numero di byte al secondo (es. 176400 byte/sec per un audio stereo a 44100 Hz)
    BlockAlign: Word;                      // Numero di byte per campione (es. 4 byte per audio stereo a 16 bit)
    BitsPerSample: Word;                   // Numero di bit per campione (es. 8, 16, 24, 32)  
  end;  
  PTWaveHeaderNoData = ^TWaveHeaderNoData;  


  TFormPlayerWave = class(TForm)
    MediaPlayer1: TMediaPlayer;
    PaintBox1: TPaintBox;
    procedure PaintBox1Paint(Sender: TObject);
    procedure FormResize(Sender: TObject);
  private
    { Private declarations }
    FFilename        : String;

    FSizeData        : Integer;
    FChannels        : byte;
    FBytesPerSample  : Cardinal;
    SFamplesPerSecond: Cardinal;
    FChunkSize       : Cardinal;
    function GetWaveInfo(const aFileName: String): Boolean;
  public
    { Public declarations }
    procedure LoadFile(const aFilename:String);
  end;



implementation

{$R *.dfm}

{ TFormPlayerWave }

function TFormPlayerWave.GetWaveInfo(const aFileName:String): Boolean;
var LFileStream  : TFileStream;
    LWaveHeader  : PTWaveHeaderNoData;
    LChunkSize   : Cardinal; 
    LnBytesRead  : integer;   
    LChunkID     : array [0..3] of AnsiChar;
begin
  Result := False;
  if Trim(FFileName).IsEmpty then Exit;
  
  try
    LFileStream := TFileStream.Create(FFileName, fmOpenRead or fmShareDenyNone);
    try
      New(LWaveHeader);
      Try      
        LFileStream.ReadBuffer(LWaveHeader^,SizeOf(TWaveHeaderNoData));
        Result := (LWaveHeader.ChunkID = 'RIFF') or (LWaveHeader.Format = 'WAVE');
        if Result then
        begin
          LFileStream.Seek(SizeOf(TWaveHeaderNoData) + 2, soFromBeginning);
          repeat
            LnBytesRead := LFileStream.Read(LChunkID, SizeOf(LChunkID));
            if LnBytesRead= 0 then Exit(false);            
            if (LnBytesRead = SizeOf(LChunkID)) and (LChunkID = 'data') then
            begin	
              LFileStream.ReadBuffer(FSizeData,sizeOf(FSizeData));
              Break; 
            end;
            LFileStream.ReadBuffer(LChunkSize,SizeOf(Cardinal));
            LFileStream.Seek(LChunkSize,soCurrent);	            
          until LnBytesRead = 0;
                 
          FChannels        := LWaveHeader.NumChannels;
          FBytesPerSample  := LWaveHeader.BitsPerSample ;
          SFamplesPerSecond:= LWaveHeader.SampleRate;
          FChunkSize       := LWaveHeader.ChunkSize;
        end;
      finally
        dispose(LWaveHeader)
      End;
    finally
      FreeAndNil(LFileStream);
    end;
  except
// do nothing
  end;
  if not Result then
    MessageBox(Handle, 'Invalid file', '', MB_OK);
end;

procedure TFormPlayerWave.LoadFile(const aFilename: String);
begin
  FFilename             := aFilename;
  GetWaveInfo(aFilename);
  MediaPlayer1.FileName := aFilename;
  MediaPlayer1.Open;
end;

procedure TFormPlayerWave.PaintBox1Paint(Sender: TObject);
const MAX_SAMPLES = 65535; // Numero massimo di campioni da disegnare
      BUFFER_SIZE = MAX_SAMPLES * 2; // Dimensione del buffer di lettura (2 byte per campione)
var LFileStream  : TFileStream;
    LWaveHeader  : PTWaveHeaderNoData;
    LChunkSize   : Cardinal; 
    LnBytesRead  : integer;   
    LChunkID     : array [0..3] of AnsiChar; 
    numSamples   : Integer; 
    buffer       : array[0..BUFFER_SIZE - 1] of Byte;
    samples      : array[0..MAX_SAMPLES - 1] of SmallInt;    
    xStep        : Single; 
    yScale       : Single;    
    i, x, y      : Integer;
begin
  if FFilename.IsEmpty then Exit;

  {TODO NOT WORK....}
  LFileStream := TFileStream.Create(FFileName, fmOpenRead or fmShareDenyNone);
  try
    New(LWaveHeader);
    Try      
      LFileStream.ReadBuffer(LWaveHeader^,SizeOf(TWaveHeaderNoData));
     LFileStream.Seek(SizeOf(TWaveHeaderNoData) + 2, soFromBeginning);
      repeat
        LnBytesRead := LFileStream.Read(LChunkID, SizeOf(LChunkID));
        if LnBytesRead= 0 then Exit;            
        if (LnBytesRead = SizeOf(LChunkID)) and (LChunkID = 'data') then
        begin	

          LFileStream.ReadBuffer(LChunkSize,SizeOf(Cardinal));
          LFileStream.Read(buffer, LChunkSize);        
          
          numSamples := Round(LChunkSize / (FChannels * FBytesPerSample / 8));
          xStep      := PaintBox1.Width/numSamples;
          yScale     := PaintBox1.Height / 32767;

          PaintBox1.Canvas.Pen.Color   := clBlack;
          PaintBox1.Canvas.Brush.Color := clWhite;
          PaintBox1.Canvas.FillRect(Rect(0, 0, PaintBox1.Width, PaintBox1.Height));
    

          PaintBox1.Canvas.MoveTo(0, PaintBox1.Height div 2);
          PaintBox1.Canvas.LineTo(PaintBox1.Width, PaintBox1.Height div 2);
       
          Move(buffer,samples,LChunkSize);
          x := 0;
          for i := 0 to numSamples - 1 do
          begin
            y :=  Round(samples[i] * yScale );
            if i = 0 then
              PaintBox1.Canvas.MoveTo(x, y)
            else
              PaintBox1.Canvas.LineTo(x, y);
         
              
            X := Round(I* xStep);
            if x >= PaintBox1.Width then
              Break;
          end;             
          Break; 
        end;
        LFileStream.ReadBuffer(LChunkSize,SizeOf(Cardinal));
        LFileStream.Seek(LChunkSize,soCurrent);	            
      until LnBytesRead = 0;
    finally
      dispose(LWaveHeader)
    End;
  finally
    FreeAndNil(LFileStream);
  end;
  
end;

procedure TFormPlayerWave.FormResize(Sender: TObject);
begin
  PaintBox1.Invalidate
end;

end.
