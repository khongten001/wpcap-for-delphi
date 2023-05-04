unit UnFormPlayerWave;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,Math,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.MPlayer,MMSystem, Vcl.ExtCtrls,system.Generics.Collections;


type
  TWaveHeader = packed record            
    ChunkID       : array [0..3] of AnsiChar; // Contiene sempre la stringa 'RIFF'
    ChunkSize     : LongWord;                 // Dimensione totale del file in byte - 8
    Format        : array [0..3] of AnsiChar; // Contiene sempre la stringa 'WAVE'
    Subchunk1ID   : array [0..3] of AnsiChar; // Contiene sempre la stringa 'fmt '
    Subchunk1Size : LongWord;                 // Dimensione del chunk fmt, fisso a 16
    AudioFormat   : Uint16;                   // Formato audio (1 = PCM)
    NumChannels   : Uint16;                   // Numero di canali (1 = mono, 2 = stereo)
    SampleRate    : LongWord;                 // Frequenza di campionamento (es. 44100 Hz)
    ByteRate      : LongWord;                 // Numero di byte al secondo (es. 176400 byte/sec per un audio stereo a 44100 Hz)
    BlockAlign    : Uint16;                   // Numero di byte per campione (es. 4 byte per audio stereo a 16 bit)
    BitsPerSample : Uint16;                   // Numero di bit per campione (es. 8, 16, 24, 32)    
  end;  
  PTWaveHeader = ^TWaveHeader;  


  TFormPlayerWave = class(TForm)
    PaintBox1: TPaintBox;
    MediaPlayer1: TMediaPlayer;
    procedure PaintBox1Paint(Sender: TObject);
  private    
    { Private declarations }    
    CONST 
      WAVE_FORMAT_PCM  = 1;
      WAVE_FORMAT_ALAW = 6;
      WAVE_FORMAT_ULAW = 7;
      WAVE_FORMAT_GSM  = 49;
    var
    FFilename   : String;
    FWaveData   : TArray<SmallInt>;
    FSampleCount: Integer;
    function GetWaveInfo(const aFileName: String): Boolean;
    function ConvertALawToPCM(const AData: TArray<Byte>): TArray<SmallInt>;
    function ConvertULawToPCM(const AData: TArray<Byte>): TArray<SmallInt>;    
  public
    { Public declarations }
    procedure LoadFile(const aFilename:String);
  end;


implementation

{$R *.dfm}

{ TFormPlayerWave }


function TFormPlayerWave.ConvertALawToPCM(const AData: TArray<Byte>): TArray<SmallInt>;
CONST
 cALawToPcm: array[0..255] of SmallInt = (-5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736, -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784, -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368, -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392, -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944, -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136, -11008, -10496, -12032, -11520, -8960, -8448, -9984, -9472, -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568, -344, -328, -376, 
   -360, -280, -264, -312, -296, -472, -456, -504, -488, -408, -392, -440, -424, -88, -72, -120, -104, -24, -8, -56, -40, -216, -200, -248, -232, -152, -136, -184, -168, -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184, -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696, -688, -656, -752, -720, -560, -528, -624, -592, -944, -912, -1008, -976, -816, -784, -880, -848, 5504, 5248, 6016, 5760, 4480, 4224, 4992, 4736, 7552, 7296, 8064, 7808, 6528, 6272, 7040, 6784, 2752, 2624,
   3008, 2880, 2240, 2112, 2496, 2368, 3776, 3648, 4032, 3904, 3264, 3136, 3520, 3392, 22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944, 30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136, 11008, 10496, 12032, 11520, 8960, 8448, 9984, 9472, 15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568, 344, 328, 376, 360, 280, 264, 312, 296, 472, 456, 504, 488, 408, 392, 440, 424, 88, 72, 120, 104, 24, 8, 56, 40, 216, 200, 248, 232, 152, 136, 184, 168, 1376, 1312, 1504, 1440, 1120, 
   1056, 1248, 1184, 1888, 1824, 2016, 1952, 1632, 1568, 1760, 1696, 688, 656, 752, 720, 560, 528, 624, 592, 944, 912, 1008, 976, 816, 784, 880, 848 );    
var I           : Integer;
    LTmpValue   : SmallInt;    
begin
  SetLength(Result, Length(AData));
  for I := 0 to High(AData) do
  begin
    LTmpValue := cALawToPcm[AData[I] and $FF]; // convert a-law to linear
    Result [I] := LTmpValue // scrivi un valore SmallInt in uscita
  end;
end;

function TFormPlayerWave.ConvertULawToPCM(const AData: TArray<Byte>): TArray<SmallInt>;
CONST         {TODO}
MuLaw : array[0..255] of Smallint  =(-32124, -31100, -30076, -29052,
 -28028, -27004, -25980, -24956, -23932, -22908, -21884, -20860,
 -19836, -18812, -17788, -16764, -15996, -15484, -14972, -14460,
 -13948, -13436, -12924, -12412, -11900, -11388, -10876, -10364,
 -9852, -9340, -8828, -8316, -7932, -7676, -7420, -7164, -6908,
 -6652, -6396, -6140, -5884, -5628, -5372, -5116, -4860, -4604,
 -4348, -4092, -3900, -3772, -3644, -3516, -3388, -3260, -3132,
 -3004, -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
 -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436, -1372,
 -1308, -1244, -1180, -1116, -1052, -988, -924, -876, -844, -812,
 -780, -748, -716, -684, -652, -620, -588, -556, -524, -492, -460,
 -428, -396, -372, -356, -340, -324, -308, -292, -276, -260, -244,
 -228, -212, -196, -180, -164, -148, -132, -120, -112, -104, -96,
 -88, -80, -72, -64, -56, -48, -40, -32, -24, -16, -8, 0, 32124,
  31100, 30076, 29052, 28028, 27004, 25980, 24956, 23932, 22908,
  21884, 20860, 19836, 18812, 17788, 16764, 15996, 15484, 14972,
  14460, 13948, 13436, 12924, 12412, 11900, 11388, 10876, 10364,
  9852, 9340, 8828, 8316, 7932, 7676, 7420, 7164, 6908, 6652, 6396,
  6140, 5884, 5628, 5372, 5116, 4860, 4604, 4348, 4092, 3900, 3772,
  3644, 3516, 3388, 3260, 3132, 3004, 2876, 2748, 2620, 2492, 2364,
  2236, 2108, 1980, 1884, 1820, 1756, 1692, 1628, 1564, 1500, 1436,
  1372, 1308, 1244, 1180, 1116, 1052, 988, 924, 876, 844, 812,
  780, 748, 716, 684, 652, 620, 588, 556, 524, 492, 460, 428, 396,
  372, 356, 340, 324, 308, 292, 276, 260, 244, 228, 212, 196, 180,
  164, 148, 132, 120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40,
  32, 24, 16, 8, 0);
const ULAW_MAX = 8192;
var I       : Integer;
    LSign    : SmallInt;
    LExponent: SmallInt;
    LMantissa: SmallInt;
begin
  SetLength(Result, Length(AData));
  for I := 0 to High(AData) do
  begin
    LSign     := (AData[I] and $80);
    LExponent := (AData[I] and $70) shr 4;
    LMantissa := (AData[I] and $0F);
    Result[I] := LMantissa shl 4 + $8;
    Result[I] := Result[I] shl LExponent + $8;
    if LSign = 0 then
      Result[I] := -Result[I];
    Result[I] := Result[I] xor ULAW_MAX;
  end;
end;

function TFormPlayerWave.GetWaveInfo(const aFileName:String): Boolean;
var LFileStream  : TFileStream;
    LWaveHeader  : PTWaveHeader;
    LChunkSize   : Cardinal; 
    LnBytesRead  : integer;   
    LChunkID     : array [0..3] of AnsiChar;
    LBufferTmp   : Array of byte;
    LTmpSample   : SmallInt;
    J            : Integer;    
    LData        : TArray<Byte>;
    Loffset      : Int64;
    FSmpleByte   : Byte;
    
  function FindChunkString(Buffer: array of byte ;ChunkString: AnsiString; var OffSet: Int64): Boolean;
  var Index     : Integer; 
      IndexStr  : Integer;
      LFound    : Boolean;
  begin
    Result := False;
    OffSet := -1;
    LFound := False;
    Index  := 0;
    while (Index <= ((Length(Buffer) - Length(ChunkString)))) and (LFound = False) do
    begin
      LFound := True;

      for IndexStr := 0 to Length(ChunkString)-1 do
        if AnsiChar(Buffer[Index + IndexStr]) <> ChunkString[IndexStr + 1] then
          LFound := False;

      if LFound then
      begin
        OffSet := Index;
        Result := True;
      end
      else
        Inc(Index);
    end;
  end;
  
begin
  Result    := False;
  if Trim(aFileName).IsEmpty then Exit;
  
  try
    LFileStream := TFileStream.Create(aFileName, fmOpenRead or fmShareDenyNone);
    try
      New(LWaveHeader);
      Try      
        LFileStream.ReadBuffer(LWaveHeader^,SizeOf(TWaveHeader));
        Result := (LWaveHeader.ChunkID = 'RIFF') or (LWaveHeader.Format = 'WAVE');
        if Result then
        begin        
          LFileStream.Seek(SizeOf(TWaveHeader), soFromBeginning);
          SetLength(LBufferTmp,80 - SizeOf(TWaveHeader));
          LFileStream.ReadBuffer(LBufferTmp[0],80 - SizeOf(TWaveHeader));
          if not FindChunkString(LBufferTmp,'data',Loffset) then
          begin
            Result := False;
            Exit;
          end;
          
          LFileStream.Position := SizeOf(TWaveHeader)+ Loffset;
          LnBytesRead := LFileStream.Read(LChunkID, SizeOf(LChunkID));
          if LnBytesRead= 0 then Exit(false);            
          LFileStream.Read(LChunkSize,SizeOf(Cardinal));	
          case LWaveHeader.AudioFormat of
            WAVE_FORMAT_PCM :
              begin 
                if LWaveHeader.BitsPerSample = 8 then
                begin
                  FSampleCount := LChunkSize;
                  SetLength(FWaveData, FSampleCount);
                  // Leggi i campioni audio dal file WAV e convertili in formato PCM a 8 bit
                  for J := 0 to FSampleCount - 1 do
                  begin
                    LFileStream.Read(FSmpleByte, 1);
                    LTmpSample := FSmpleByte * 256 - 32768;
                    FWaveData[J] := LTmpSample;
                  end;                 
                end
                else
                begin
                  FSampleCount := LChunkSize div 2;
                  SetLength(FWaveData, FSampleCount);
                  // Leggi i campioni audio dal file WAV e convertili in formato PCM a 8 bit
                  for J := 0 to FSampleCount - 1 do
                  begin
                    LFileStream.Read(LTmpSample, 2);
                    FWaveData[J] := Round((LTmpSample / 32768.0) * 128.0);
                  end;   
                end;            
              end;
            WAVE_FORMAT_ALAW  :
              begin
                SetLength(LData, LChunkSize);
                LFileStream.ReadBuffer(LData[0], LChunkSize);
                FWaveData := ConvertALawToPCM(LData);
              end;
            WAVE_FORMAT_ULAW :
              begin
                SetLength(LData, LChunkSize);
                LFileStream.ReadBuffer(LData[0], LChunkSize);
                FWaveData := ConvertULawToPCM(LData);                  
              end;
          end;
        end
        else Exit;
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
  if not GetWaveInfo(aFilename) then  Exit;
  
  FFilename  := aFilename;
  Try
    MediaPlayer1.FileName := FFilename;
    MediaPlayer1.Open;
  except on E: Exception do
    ShowMessage('Error loading file ' + aFilename + ': ' + E.Message);
  End;
end;

procedure TFormPlayerWave.PaintBox1Paint(Sender: TObject);
var I               : Integer;
    LMaxValue       : Double;
    LScaleFactor    : Double; 
    LPeakThreshold  : Double;
    LDataSize       : Integer;
    LZeroCrossCount : Integer;

    LSecDrivative   : array of Double;
    
  procedure CalculateSecDerivative;
  var I : Integer;
  begin
    SetLength(LSecDrivative, LDataSize);
    for i := 1 to LDataSize - 1 do
      LSecDrivative[i] := Sign(FWaveData[i]) - Sign(FWaveData[i - 1]);
  end;

  procedure CountZeroCrossings;
  var LLastSign    : Integer; 
      LCurrentSign : Integer;
      I            : Integer;      
  begin
    LZeroCrossCount := 0;
    for i := 1 to LDataSize - 1 do
    begin
      LLastSign    := Sign(LSecDrivative[i - 1]);
      LCurrentSign := Sign(LSecDrivative[i]);
      if (LLastSign > 0) and (LCurrentSign < 0) then
        Inc(LZeroCrossCount);
    end;
  end;

  function GetScaledValue(const value: Double): Integer;
  begin
    Result := Round(value * LScaleFactor * (PaintBox1.Height / High(SmallInt)) / 2);
  end;

begin
  PaintBox1.Canvas.Lock;
  try
    // Draw background
    PaintBox1.Canvas.Brush.Color := $00323232;
    PaintBox1.Canvas.FillRect(PaintBox1.Canvas.ClipRect);

    // Draw horizontal line
    PaintBox1.Canvas.Pen.Color := $00FFDAAF;
    PaintBox1.Canvas.MoveTo(0, PaintBox1.Height div 2);
    PaintBox1.Canvas.LineTo(PaintBox1.Width, PaintBox1.Height div 2);

    LmaxValue := 0;
    LDataSize := Length(FWaveData);
    for i := 0 to LDataSize - 1 do
      if Abs(FWaveData[i]) > LmaxValue then
        LmaxValue := Abs(FWaveData[i]);

    CalculateSecDerivative;
    CountZeroCrossings;

    LScaleFactor := High(SmallInt) / LmaxValue;
    LpeakThreshold := LmaxValue * 0.75;

    PaintBox1.Canvas.Pen.Color := Clwhite;
    PaintBox1.Canvas.Pen.Width := 2; 
    for i := 1 to LDataSize - 1 do
    begin
      if (Abs(FWaveData[i]) >= LpeakThreshold) and (Sign(FWaveData[i]) - Sign(FWaveData[i - 1]) < 0) and (LZeroCrossCount > 0) then
      begin
        PaintBox1.Canvas.Pen.Color := clRed;
        Dec(LZeroCrossCount);
      end
      else
        PaintBox1.Canvas.Pen.Color := Clwhite;

      PaintBox1.Canvas.MoveTo(Round((i - 1) * (PaintBox1.Width / LDataSize)), PaintBox1.Height div 2 - GetScaledValue(FWaveData[i - 1]));
      PaintBox1.Canvas.LineTo(Round(i * (PaintBox1.Width / LDataSize)), PaintBox1.Height div 2 - GetScaledValue(FWaveData[i]));
    end;
    
  finally 
     PaintBox1.Canvas.Unlock 
  end; 
end;
     
end.
