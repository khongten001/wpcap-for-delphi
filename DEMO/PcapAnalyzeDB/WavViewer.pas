unit WavViewer;

interface

uses
  Windows, SysUtils, Classes, Controls, Forms, Graphics, Math, Messages,
    MMSystem, ExtCtrls;

type
  PTWord=^TWordArray;
  TWordArray=array[0..29999] of Word;   // size of buffers optimized for PIV 2.4, 384 mb.RAM
  
  PTShortInt = ^TShortInt;
  TShortInt = array[0..59999] of ShortInt;

  WMPTimeFormats = (tfMilliseconds, tfBytes, tfSamples); // only these ones valid for WAV
  WMPModes       = (mpNotReady, mpStopped, mpPlaying, mpPaused, mpOpen);  // no Record implemented

  TBuildingPeaksProc = procedure (Sender: TObject;BytesRead:Integer; PercentDone:Single;var BreakProcess:boolean) of object;
  TPaintProc         = procedure (Sender:TObject;Canvas:TCanvas) of object;
  TScrollProc        = procedure (Sender:TObject;ScrollCode:Integer;var ScrollPos:Integer) of object;
  TMouseProc         = procedure (Sender:TObject;LeftButton:Boolean;X:Integer;Y:Integer) of object;
  TPlayingProc       = procedure (Sender:TObject;TimerId:Integer;PlayingPos:Integer) of object;

  TMyPanel = class;





  TWavViewer = class(TWinControl)
  private
    AutoMove: Boolean;
    FBitmap: TBitmap;
    FAutoLoop: Boolean;
    FBorderColor: TColor;
    FFileName: TFileName;
    FLargeChange: Byte;
    FMarksColor: TColor;
    FMarksInterval: Byte;
    FOnBuildingPeaks: TBuildingPeaksProc;
    FOnButtonDown: TMouseProc;
    FOnPaint: TPaintProc;
    FOnPaintHorzInfo: TPaintProc;
    FOnPaintVertInfo: TPaintProc;
    FOnPlaying: TPlayingProc;
    FOnReadBytes: TBuildingPeaksProc;
    FOnScroll: TScrollProc;
    FPeaksColor: TColor;
    FPointerColor: TColor;
    FPositionColor: TColor;
    FSmallChange: Byte;
    FStartPos: DWORD;
    FTimerInterval: Integer;
    FSavePeaks: Boolean;
    DoAutoLoop: Boolean;
    InfoHorz: TMyPanel;
    InfoVert: TMyPanel;
    MCIOpened: Boolean;
    MemoryBitmap: HBitmap;
    MemoryCanvas: TCanvas;
    OldBitmap: HBitmap;
    OldMark: Integer;
    PeaksExt: string;
    TimerID: Integer;
    FChunkSize: integer;
    procedure CMColorChanged(var Message: TMessage); message CM_COLORCHANGED;
    procedure CMFontChanged(var Message: TMessage); message CM_FONTCHANGED;
    function GetBevelInner:TPanelBevel;
    function GetBevelOuter:TPanelBevel;
    function GetBevelWidth:TBevelWidth;
    function GetInfoBackColor:TColor;
    function GetInfoBorderWidth:TBorderWidth;
    function GetInfoBorderStyle:TBorderStyle;
    function GetInfoHeight:Integer;
    function GetInfoWidth:Integer;
    function GetMode: WMPModes;
    function GetPosition:DWORD;
    function GetScrollPosition:Integer;
    function GetStartPos:DWORD;
    function GetTimeFormat:WMPTimeFormats;
    function GetTrackInfo:Boolean;
    function GetTrackLength:DWORD;
    procedure SetBitmap(f:string);
    procedure SetBevelInner(Value:TPanelBevel);
    procedure SetBevelOuter(Value:TPanelBevel);
    procedure SetBevelWidth(Value:TBevelWidth);
    procedure SetBorderColor(aColor:TColor);
    procedure SetFileName(aFilename:TFileName);
    procedure SetInfoBackColor(aColor:TColor);
    procedure SetInfoBorderWidth(aValue:TBorderWidth);
    procedure SetInfoBorderStyle(aValue:TBorderStyle);
    procedure SetInfoHeight(aHeight:Integer);
    procedure SetInfoWidth(aWidth:Integer);
    procedure SetLargeChange(l:Byte);
    procedure SetMarksColor(aColor:TColor);
    procedure SetMarksInterval(aInterval:Byte);
    procedure SetPeaksExt(s:string);
    procedure SetPeaksColor(aColor:TColor);
    procedure SetPositionColor(aColor:TColor);
    procedure SetPosition(p:DWORD);
    procedure SetScrollPosition(p:Integer);
    procedure SetSmallChange(l:Byte);
    procedure SetStartPos(p:DWORD);
    procedure SetTimeFormat(f:WMPTimeFormats);
    procedure SetTimerInterval(aInterval:Integer);
    procedure UpdateScroll;
    function GetSecondoToShow: Integer;
  protected
    procedure CreateParams(var Params: TCreateParams);override;
    procedure DoMouse(coordx:Integer);virtual;
    procedure DoScroll(ScrollCode:Word);virtual;
    procedure DoPaintHorzInfo(aCanvas:TCanvas);virtual;
    procedure DoPaintVertInfo(aCanvas:TCanvas);virtual;
    procedure DoPaintWindow(CopyCanvas:Boolean=true;Canvas:TCanvas=nil);virtual;
    procedure DoTimer;virtual;
    procedure WndProc(var Message:TMessage);override;
  public
    BytesPerSample:Byte;
    Channels:Byte;
    DeviceID:MCIDEVICEID;
    Peaks:TMemoryStream;
    SamplesPerSecond:Integer;
    FSizeData:Cardinal;
    constructor Create(AOwner: TComponent);override;
    destructor Destroy; override;
    function BuildPeaks:Boolean;
    procedure CloseMedia;
    function FormatTimeToMilliseconds(ftime:DWORD):DWORD;
    function GetPeaksCount:DWORD;
    procedure GoToSecond(s:Integer);
    function MillisecondsToPeaks(p:Integer):Integer;
    function MillisecondsToPixels(p:Integer):Integer;
    function MillisecondsToFormatTime(ms:DWORD):DWORD;
    procedure OpenMedia;
    procedure Pause;
    function PeaksToPixels(p:Integer):Integer;
    function PeaksToMilliseconds(p:DWORD):DWORD;
    function PixelsToMilliseconds(p:Integer):Integer;
    function PixelsToPeaks(p:Integer):Integer;
    function PeaksToSamples(p:DWORD):DWORD;
    procedure Play(UseFrom:Boolean=True;StartPos:DWORD=0);
    property PositionImage:string write SetBitmap;
    function ReadBytes(Buffer:TMemoryStream;start,sizebuffer:Integer;var length:Integer):Boolean;
    function ReadHeader(Buffer:Pointer):Boolean;
    function SavePeaksToFile(FileName:TFileName=''):Boolean;
    procedure Stop;
    property Length:DWORD read GetTrackLength;
    property MediaMode: WMPModes read GetMode;
    property MediaPosition:DWORD read GetPosition write SetPosition;
    property ScrollPosition:Integer read GetScrollPosition write SetScrollPosition;
    property StartPos:DWORD read GetStartPos write SetStartPos;
    property TimeFormat:WMPTimeFormats read GetTimeFormat write SetTimeFormat;
  published
    property Align;
    property Anchors;
    property AutoLoop:Boolean read FAutoLoop write FAutoLoop;
    property ClientHeight;
    property ClientWidth;
    property Enabled;
    property InfoBevelInner: TPanelBevel read GetBevelInner write SetBevelInner
      default bvNone;
    property InfoBevelOuter: TPanelBevel read GetBevelOuter write SetBevelOuter
      default bvRaised;
    property InfoBevelWidth: TBevelWidth read GetBevelWidth write SetBevelWidth
      default 1;
    property BorderColor:TColor read FBorderColor write SetBorderColor;
    property InfoBorderWidth:TBorderWidth read GetInfoBorderWidth write SetInfoBorderWidth
      default 0;
    property InfoBorderStyle: TBorderStyle read GetInfoBorderStyle write SetInfoBorderStyle
      default bsNone;
    property Color;
    property FileName:TFileName read FFileName write SetFileName;
    property Font;
    property InfoBackColor:TColor read GetInfoBackColor write SetInfoBackColor;
    property InfoHeight:Integer read GetInfoHeight write SetInfoHeight;
    property InfoWidth:Integer read GetInfoWidth write SetInfoWidth;
    property LargeChangeSeconds:Byte read FLargeChange write SetLargeChange;
    property MarksColor:TColor read FMarksColor write SetMarksColor;
    property MarksInterval:Byte read FMarksInterval write SetMarksInterval;
    property PeaksFileExt:string read PeaksExt write SetPeaksExt;
    property PeaksColor:TColor read FPeaksColor write SetPeaksColor;
    property PointerColor:TColor read FPointerColor write FPointerColor;
    property PositionColor:TColor read FPositionColor write SetPositionColor;
    property SecondsToShow:Integer read GetSecondoToShow;
    property SmallChangeSeconds:Byte read FSmallChange write SetSmallChange;
    property PlayingInterval:Integer read FTimerInterval write SetTimerInterval;
    property SavePeaks:Boolean read FSavePeaks write FSavePeaks;
    property TabOrder;
    property TabStop;
    property Visible;
    property OnBuildingPeaks:TBuildingPeaksProc read FOnBuildingPeaks write FOnBuildingPeaks;
    property OnButtonDown:TMouseProc read FOnButtonDown write FOnButtonDown;
    property OnEnter;
    property OnExit;
    property OnKeyDown;
    property OnKeyPress;
    property OnKeyUp;
    property OnPaint:TPaintProc read FOnPaint write FOnPaint;
    property OnPaintHorzInfo:TPaintProc read FOnPaintHorzInfo write FOnPaintHorzInfo;
    property OnPaintVertInfo:TPaintProc read FOnPaintVertInfo write FOnPaintVertInfo;
    property OnPlaying:TPlayingProc read FOnPlaying write FOnPlaying;
    property OnReadBytes:TBuildingPeaksProc read FOnReadBytes write FOnReadBytes;
    property OnScroll:TScrollProc read FOnScroll write FOnScroll;
  end;

  TMyPanel = class(TCustomPanel)
  protected
    procedure WndProc(var Message: TMessage); override;
  end;


procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('Samples', [TWavViewer]);
end;

constructor TWavViewer.Create(AOwner: TComponent);
begin
  Peaks    := TMemoryStream.Create;
  InfoHorz := TMyPanel.Create(Self);
  InfoVert := TMyPanel.Create(Self);
  inherited Create(AOwner);
  Constraints.MinHeight := 48;
  Constraints.MinWidth  := 46;
  FMarksInterval        := 7;
  FPointerColor         := clBlack;
  with InfoHorz do
  begin
    Parent     := Self;
    BevelWidth := 2;
    Width      := 26;
    Tag        := 0;
    Align      := alLeft;
  end;
  with InfoVert do
  begin
    Parent    := Self;
    BevelWidth:= 2;
    Height    := 28;
    Tag       := 1;
    Align     := alTop;
  end;
  Font.Name     := 'Arial Narrow';
  Font.Size     := 9;
  FLargeChange  := 40;
  FSmallChange  := 10;
  PeaksExt      := '.pek';
  Color         := clWhite;
  FBorderColor  := clBlack;
  FPeaksColor   := clBlue;
  FPositionColor:= ClRed;
  FTimerInterval:= 100;
  FSavePeaks    := False;
  OldMark       := 0;
end;

procedure TWavViewer.CreateParams(var Params: TCreateParams);
begin
  inherited CreateParams(Params);
  Params.Style := Params.Style or WS_HSCROLL;
end;

destructor TWavViewer.Destroy;
begin
  CloseMedia;
  SelectObject(MemoryCanvas.Handle,OldBitmap);
  DeleteObject(MemoryBitmap);
  MemoryCanvas.Free;
  Peaks.Clear;
  Peaks.Free;
  FBitmap.Free;
  inherited Destroy;
end;

function TWavViewer.BuildPeaks:Boolean;
var
  ChunkID: array[0..3] of AnsiChar;
  ChunkSize: Cardinal;
  LFileStream: TFileStream;
  nResolution: Integer;
  nBytesToRead, nBytesRead: Integer;
  Iterator, nPosition: Integer;
  bAssigned, bProcess: Boolean;

  procedure SafeNumber(var n:Integer);
  begin
    while n mod BytesperSample <> 0 do
      Inc(n);
  end;

  procedure TakeData8m;
  var LBuffer: PByte;
      LPeek  : array[0..1] of Byte;
      r      : ShortInt;
      b      : Byte;
  begin
    GetMem(LBuffer, nBytesToRead);
    Try
      for b := 0 to 1 do
        LPeek[b] := 127;
      Iterator  := 0;
      nPosition := 0;
      repeat
        nBytesRead := LFileStream.Read(LBuffer^, nBytesToRead);
        while Iterator - nPosition < nBytesRead do
        begin
          r := ShortInt(LBuffer[Iterator - nPosition]) - 128;
          if r > 0 then
          begin
            if r < ShortInt(LPeek[1]) - 128 then
              LPeek[1] := r + 128;
          end
          else
          begin
            b := r + 128;
            if b > LPeek[0] then
              LPeek[0] := b;
          end;
          if ((Iterator + 1) mod nResolution = 0) or ((Iterator - nPosition + 1 >= nBytesRead) and (nBytesRead < nBytesToRead)) then
          begin
            Peaks.Write(LPeek, SizeOf(LPeek));
            for b := 0 to 1 do
              LPeek[b] := 127;
          end;
          Inc(Iterator);
        end;
        Inc(nPosition, nBytesRead);
        if bAssigned then
          FOnBuildingPeaks(Self, nPosition, nPosition / FSizeData, bProcess);
      until (not bProcess) or (nBytesRead < nBytesToRead);
    Finally
      FreeMem(LBuffer);
    End;    
  end;


  procedure TakeData16m;
  var
    Buffer: PTWord;
    pk: array[0..1] of Word;
    r: Word;
  begin
    GetMem(Buffer, nBytesToRead);
    for r := 0 to 1 do
      pk[r] := 32767;
    Iterator := 0;
    nPosition := 0;
    repeat
      nBytesRead := LFileStream.Read(Buffer^, nBytesToRead);
      while (Iterator - nPosition) * 2 < nBytesRead do
      begin
        r := Buffer[Iterator - nPosition] + 32768;
        if r < 32768 then
        begin
          if r < pk[1] then
            pk[1] := r;
        end
        else if r > pk[0] then
          pk[0] := r;
        if ((Iterator + 1) mod nResolution = 0) or ((((Iterator - nPosition) * 2) + 2 >= nBytesRead) and (nBytesRead < nBytesToRead)) then
        begin
          Peaks.Write(pk, sizeof(pk));
          for r := 0 to 1 do
            pk[r] := 32767;
        end;
        Inc(Iterator);
      end;
      Inc(nPosition, Round(nBytesRead / 2));
      if bAssigned then
        FOnBuildingPeaks(Self, nPosition * 2, nPosition * 2 / FSizeData, bProcess);
    until (not bProcess) or (nBytesRead < nBytesToRead);
    FreeMem(Buffer);
  end;

  procedure TakeData8s;
  var
    Buffer: PTShortInt;
    pk: array[0..3] of Byte;
    b: Byte;
    r: ShortInt;
  begin
    GetMem(Buffer, nBytesToRead);
    for b := 0 to 3 do
      pk[b] := 127;
    Iterator := 0;
    nPosition := 0;
    repeat
      nBytesRead := LFileStream.Read(Buffer^, nBytesToRead);
      while (Iterator - nPosition) * 2 < nBytesRead do
      begin
        r := Buffer[Iterator - nPosition];
        if r > 0 then
        begin
          if r < ShortInt(pk[1]) then
            pk[1] := r;
        end
        else
        begin
          b := r;
          if b > pk[0] then
            pk[0] := b;
        end;
        r := Buffer[Iterator - nPosition + 1];
        if r > 0 then
        begin
          if r < ShortInt(pk[3]) then
            pk[3] := r;
        end
        else
        begin
          b := r;
          if b > pk[2] then
            pk[2] := b;
        end;
        if ((Iterator + 2) mod nResolution = 0) or ((((Iterator - nPosition) * 2) + 4 >= nBytesRead) and (nBytesRead < nBytesToRead)) then
        begin
          Peaks.Write(pk, sizeof(pk));
          for b := 0 to 3 do
            pk[b] := 127;
        end;
        Inc(Iterator, 2);
      end;
      Inc(nPosition, Round(nBytesRead / 2));
      if bAssigned then
        FOnBuildingPeaks(Self, Round(nPosition / 2), (nPosition / 2) / FSizeData, bProcess);
    until (not bProcess) or (nBytesRead < nBytesToRead);
    FreeMem(Buffer);
  end;

  procedure TakeData16s;
  var
    Buffer: PTWord;
    pk: array[0..3] of Word;
    r: Word;
  begin
    GetMem(Buffer, nBytesToRead);
    for r := 0 to 3 do
      pk[r] := 32767;
    Iterator := 0;
    nPosition := 0;
    repeat
      nBytesRead := LFileStream.Read(Buffer^, nBytesToRead);
      while (Iterator - nPosition) * 4 < nBytesRead do
      begin
        r := Buffer[Iterator - nPosition] + 32768;
        if r < 32768 then
        begin
          if r < pk[1] then
            pk[1] := r;
        end
        else if r > pk[0] then
          pk[0] := r;
        r := Buffer[Iterator - nPosition + 1] + 32768;
        if r < 32768 then
        begin
          if r < pk[3] then
            pk[3] := r;
        end
        else if r > pk[2] then
          pk[2] := r;
        if ((Iterator + 2) mod nResolution = 0) or ((((Iterator - nPosition) * 4) + 8 >= nBytesRead) and (nBytesRead < nBytesToRead)) then
        begin
          Peaks.Write(pk, sizeof(pk));
          for r := 0 to 3 do
            pk[r] := 32767;
        end;
        Inc(Iterator, 2);
      end;
      Inc(nPosition, Round(nBytesRead / 4));
      if bAssigned then
        FOnBuildingPeaks(Self, nPosition * 4, nPosition * 4 / FSizeData, bProcess);
      if not bProcess then
        break;
    until nBytesRead < nBytesToRead;
    FreeMem(Buffer);
  end;

var WaveHeader: PTWaveHeaderNoData;
begin
  Result   := false;
  bProcess := true;
  if FSizeData=0 then
    if not GetTrackInfo then exit;
  try
    LFileStream := TFileStream.Create(FFileName, fmOpenRead or fmShareDenyNone);
    try
      New(WaveHeader);
      Try      
        LFileStream.ReadBuffer(WaveHeader^,SizeOf(TWaveHeaderNoData));    
        LFileStream.Seek(SizeOf(TWaveHeaderNoData)+2, soFromBeginning);      
        repeat       
          nBytesRead := LFileStream.Read(ChunkID, SizeOf(ChunkID));
       
          if nBytesRead= 0 then Exit;

          if (nBytesRead = SizeOf(ChunkID)) and (ChunkID = 'data') then
          begin
            LFileStream.Seek(4, soFromCurrent);
            Peaks.Clear;
            
            nResolution := Round(SecondsToShow * SamplesperSecond / (ClientWidth - InfoHorz.Width));
            if nResolution *  (ClientWidth - InfoHorz.Width) > 60000 then
              nBytesToRead := 60000
            else
              nBytesToRead := Round(nResolution * (ClientWidth - InfoHorz.Width));
              
            SafeNumber(nBytesToRead);
            Peaks.Clear;
            SafeNumber(nResolution);
            bAssigned := Assigned(FOnBuildingPeaks);

            if BytesPerSample = 1 then
              TakeData8m
            else if (BytesPerSample = 2) and (Channels = 1) then
              TakeData16m
            else if BytesPerSample = 2 then
              TakeData8s
            else
              TakeData16s;

            Result := true;
            if FSavePeaks then
              SavePeaksToFile;
            Cursor := crHandPoint;
            UpdateScroll;
            break;
          end;
        
          // Not the "data" chunk, skip to the next chunk
          LFileStream.ReadBuffer(ChunkSize,SizeOf(Cardinal));
          LFileStream.Seek(ChunkSize,soCurrent);
        until nBytesRead  = 0
      finally
        Dispose(WaveHeader)
      end;
    finally
      LFileStream.Free;
    end;
  except
  end;
end;

procedure TWavViewer.CloseMedia;
var
  GenParm: TMCI_Generic_Parms;
  f: MCIERROR;
begin
  if MCIOPened then
  begin
    f := mciSendCommand(DeviceID, mci_Close, 0, DWORD(@GenParm));
    if f = 0 then
    begin
      DeviceID := 0;
      MCIOpened := false;
    end;
  end;
end;

procedure TWavViewer.CMColorChanged(var Message: TMessage);
begin
  if MemoryCanvas <> nil then
    DoPaintWindow;
end;

procedure TWavViewer.CMFontChanged(var Message: TMessage);
begin
  InfoHorz.Font.Assign(Font);
  if Parent <> nil then
    InfoHorz.Constraints.MinWidth := InfoHorz.Canvas.TextWidth('0000')
  else
    InfoHorz.Constraints.MinWidth := 32;
  InfoVert.Font.Assign(Font);
  if Parent <> nil then
    InfoVert.Constraints.MinHeight := InfoHorz.Canvas.TextHeight('H') + 10
  else
    InfoVert.Constraints.MinHeight := 28;
end;

procedure TWavViewer.DoMouse(coordx:Integer);
var
  i:DWORD;
begin
  i:=FStartPos;
  FStartPos:=PixelsToMilliseconds((coordx-InfoHorz.Width)+GetScrollPosition);
  if i<>FStartPos then
    DoPaintWindow;
end;

procedure TWavViewer.DoPaintHorzInfo(aCanvas: TCanvas);
var
  LPw, LCoord, z: Integer;
  Lcshow: Byte;
begin
  with aCanvas do
  begin
    Pen.Width := 1;
    Pen.Style := psSolid;
    Pen.Color := BorderColor;

    if FSizeData = 0 then
      Lcshow := 2
    else
      Lcshow := Channels;
      
    LPw   := Round(InfoHorz.Height / (Lcshow * 2));
    LCoord := LPw;
    for z := 1 to Lcshow do
    begin
      MoveTo(0, LCoord);
      LineTo(InfoHorz.Width, LCoord);
      TextOut((InfoHorz.Width - TextWidth('0')) div 2, LCoord - (TextHeight('0') + 2), '0');
      Inc(LCoord, LPw * 2);
    end;
    
    if Lcshow = 2 then
    begin
      Pen.Width := 2;
      MoveTo(0, LPw * 2);
      LineTo(InfoHorz.Width, LPw * 2);
    end;
    
  end;
end;



procedure TWavViewer.DoPaintVertInfo(aCanvas: TCanvas);
var
  pw, coord, y: Integer;
  rgn: HRgn;
  p: array[0..2] of TPoint;
  t: TDateTime;
  s: string;
begin
  with aCanvas do
  begin

    Brush.Color := FMarksColor;
    Brush.Style := bsSolid;
    SetBkMode(Handle, TRANSPARENT);

    pw := MillisecondsToPixels(FMarksInterval * 1000);
    if pw = 0 then
      pw := Round(((ClientWidth - InfoHorz.Width) * FMarksInterval) / SecondsToShow);

    coord := pw;
    p[0]  := Point(0, 1);
    p[1]  := Point(0, 7);
    p[2]  := Point(0, 1);

    y := ScrollPosition + (FMarksInterval * 1000);

    while coord < InfoVert.Width do
    begin
      p[0].X := coord - 3;
      p[1].X := coord;
      p[2].X := coord + 3;
      rgn    := CreatePolygonRgn(p, 3, ALTERNATE);
      PaintRgn(Handle, rgn);
      DeleteObject(rgn);

      t := EncodeTime(y div 3600000, (y mod 3600000) div 60000, ((y mod 3600000) mod 60000) div 1000, y mod 1000);
      s := FormatDateTime('hh:nn:ss', t);
      TextOut(coord - (TextWidth(s) div 2), InfoVert.Height - (TextHeight(s) + 2), s);

      Inc(coord, pw);
      Inc(y, FMarksInterval * 1000)
    end;
  end;
end;

procedure TWavViewer.DoPaintWindow(CopyCanvas: Boolean = True; Canvas: TCanvas = nil);
var
  Scale: Single;
  Parts, J, Z, T, I, NLeft, NTop: Integer;
  W: Word;
  B: Byte;
  Big: Boolean;
  ChannelsShow: Byte;
  R: TRect;
  Dummy: HWnd;
    pw: DWORD;
begin
  if FSizeData = 0 then
    ChannelsShow := 2
  else
    ChannelsShow := Channels;

  Parts := ChannelsShow * 2;
  PW := Round(InfoHorz.Height / Parts);
  NLeft := InfoHorz.Width;
  NTop := InfoVert.Height;

  with MemoryCanvas do
  begin
    Brush.Color := Color;
    Brush.Style := bsSolid;
    FillRect(ClipRect);

    if Peaks.Size > 0 then
    begin
      Big := BytesPerSample / ChannelsShow = 2;

      if Big then
        Scale := 65535 / (PW * 2)
      else
        Scale := 255 / (PW * 2);

      Pen.Color := FPeaksColor;
      Pen.Width := 1;

      for J := 1 to PW div 2 do
      begin
        Z := PixelsToPeaks(GetScrollPosition) + ((J - 1) * ChannelsShow);
        Peaks.Seek(Z * Round(BytesPerSample / ChannelsShow), soFromBeginning);
        MoveTo(NLeft, NTop + (J * 2 * PW) - PW);

        for I := NLeft to ClientWidth - 1 do
        begin
          for T := 1 to 2 do
          begin
            if Big then
              Peaks.Read(W, SizeOf(Word))
            else
            begin
              Peaks.Read(B, SizeOf(Byte));
              W := Word(B);
            end;
            LineTo(I, Round((NTop + (J * 2 * PW)) - (W / Scale)));
          end;

          if ChannelsShow = 2 then
            Peaks.Seek(BytesPerSample, soFromCurrent);
        end;
      end;
    end;

    Pen.Color := FBorderColor;

    for I := 1 to Parts do
    begin
      Pen.Width := IfThen(I mod 2 = 0, 2, 1);
      MoveTo(NLeft, NTop + (I * PW));
      LineTo(ClientWidth, NTop + (I * PW));
    end;

    if Peaks.Size > 0 then
    begin
      T := MillisecondsToPixels(FStartPos) - GetScrollPosition;

      if (T > 0) and (T < ClientWidth) then
      begin
        if FBitmap = nil then
        begin
          Brush.Color := FPositionColor;
          Brush.Style := bsSolid;
          Pen.Color := FPositionColor;
          T := NLeft + T;
          Rectangle(T - 3, NTop, T + 4, NTop + 3);
          Rectangle(T - 3, ClientHeight - 3, T + 4, ClientHeight);
          MoveTo(T, NTop + 3);
          LineTo(T, ClientHeight - 3);
        end
        else
          Draw(NLeft + T - (FBitmap.Width div 2), NTop, FBitmap);
      end;

      OldMark := 0;
    end;

    Pen.Width := 2;
    Pen.Color := FBorderColor;
    Brush.Style := bsClear;
    Rectangle(NLeft, NTop,ClientWidth, ClientHeight);
    if CopyCanvas then
    begin
      // Check if we need to create a new canvas to copy to
      if Canvas = nil then
      begin
        Canvas := TCanvas.Create;
        dummy := Self.Handle;
        Canvas.Handle := GetDeviceContext(dummy);
      end;
  
      r := Rect(nleft, ntop, ClientWidth, ClientHeight);
      Canvas.CopyRect(r, MemoryCanvas, r);
  
      // If we created a new canvas, we need to free it
      if Canvas <> nil then
        Canvas.Free;
    end;
  end;
end;

procedure TWavViewer.DoScroll(ScrollCode: Word);
var
  LScollInfo: TScrollInfo;
  nPos: Integer;
  ntpos: Integer;
begin
  ZeroMemory(@LScollInfo, sizeof(LScollInfo));
  LScollInfo.cbSize := sizeof(TScrollInfo);
  LScollInfo.fMask  := SIF_RANGE or SIF_POS or SIF_TRACKPOS;
  GetScrollInfo(Handle, SB_HORZ, LScollInfo);
  nPos := LScollInfo.nPos;
  
  case ScrollCode of
    SB_BOTTOM         : nPos := LScollInfo.nMax;
    SB_LINEDOWN       : Inc(nPos, MillisecondsToPixels(FSmallChange * 1000));
    SB_LINEUP         : Dec(nPos, MillisecondsToPixels(FSmallChange * 1000));
    SB_PAGEDOWN       : Inc(nPos, MillisecondsToPixels(FLargeChange * 1000));
    SB_PAGEUP         : Dec(nPos, MillisecondsToPixels(FLargeChange * 1000));
    SB_THUMBPOSITION, 
    SB_THUMBTRACK     : nPos := LScollInfo.nTrackPos;
    SB_TOP            : nPos := LScollInfo.nMin;
  end;

  if (ScrollCode <> SB_ENDSCROLL) and (nPos <> LScollInfo.nPos) then
  begin
    LScollInfo.nPos  := Min(LScollInfo.nMax, Max(LScollInfo.nMin, nPos));
    LScollInfo.fMask := SIF_POS;
    SetScrollInfo(Handle, SB_HORZ, LScollInfo, true);
    DoPaintWindow;
    ntpos    := MillisecondsToPixels(FormatTimeToMilliseconds(GetPosition));
    AutoMove := (ntpos >= LScollInfo.nPos) and (ntpos <= LScollInfo.nPos + (ClientWidth - InfoHorz.Width));
    InfoVert.Invalidate;
  end;
end;

procedure TWavViewer.DoTimer;
var
  dc: HDC;
  pn, antpn: HPen;
  px: Integer;
  si: TScrollInfo;
begin
  if GetPosition = GetTrackLength then
    KillTimer(Handle, TimerID)
  else
  begin
    dc    := GetDC(Handle);
    pn    := CreatePen(PS_SOLID, 1, FPointerColor);
    antpn := SelectObject(dc, pn);
    SetRop2(dc, R2_NOTXORPEN);
    
    if OldMark > 0 then
    begin
      MoveToEx(dc, OldMark, InfoVert.Height, nil);
      LineTo(dc, OldMark, ClientHeight);
    end;

    px      := MillisecondsToPixels(FormatTimeToMilliseconds(GetPosition));
    OldMark := InfoHorz.Width + px - GetScrollPosition;
    
    if (OldMark > ClientWidth) and (AutoMove) then
    begin
      ZeroMemory(@si, sizeof(TScrollInfo));
      si.cbSize := sizeof(TScrollInfo);
      si.fMask  := SIF_RANGE or SIF_POS;
      GetScrollInfo(Handle, SB_HORZ, si);
      si.nPos := Min(si.nMax, Max(si.nPos + MillisecondsToPixels(FLargeChange * 1000), si.nPos + 10));
      SetScrollInfo(Handle, SB_HORZ, si, true);
      DoPaintWindow;
    end
    else if (OldMark > InfoHorz.Width) and (OldMark < ClientWidth) then
    begin
      MoveToEx(dc, OldMark, InfoVert.Height, nil);
      LineTo(dc, OldMark, ClientHeight);
    end
    else
      OldMark := 0;
      
    SelectObject(dc, antpn);
    DeleteObject(pn);
    ReleaseDC(Handle, dc);
  end;
end;

function TWavViewer.FormatTimeToMilliseconds(ftime: DWORD): DWORD;
var tf: WMPTimeFormats;
begin
  tf := GetTimeFormat;
  case tf of
    tfMilliseconds: Result := ftime;
    tfBytes       : Result := Round((ftime / (DWORD(SamplesPerSecond) * DWORD(BytesPerSample))) * 1000);
  else
    Result := Round((ftime / DWORD(SamplesPerSecond)) * 1000);
  end;
end;

function TWavViewer.GetBevelInner: TPanelBevel;
begin
  Result := InfoHorz.BevelInner;
end;

function TWavViewer.GetBevelOuter: TPanelBevel;
begin
  Result := InfoHorz.BevelOuter;
end;

function TWavViewer.GetBevelWidth: TBevelWidth;
begin
  Result := InfoHorz.BevelWidth;
end;

function TWavViewer.GetInfoBackColor: TColor;
begin
  Result := InfoHorz.Color;
end;

function TWavViewer.GetInfoBorderWidth: TBorderWidth;
begin
  Result := InfoHorz.BorderWidth;
end;

function TWavViewer.GetInfoBorderStyle: TBorderStyle;
begin
  Result := InfoHorz.BorderStyle;
end;

function TWavViewer.GetInfoHeight: Integer;
begin
  Result := InfoVert.Height;
end;

function TWavViewer.GetInfoWidth: Integer;
begin
  Result := InfoHorz.Width;
end;

function TWavViewer.GetMode: WMPModes;
var
  StatusParm: TMCI_Status_Parms;
  d: DWORD;
begin
  StatusParm.dwItem := mci_Status_Mode;
  mciSendCommand(DeviceID, mci_Status, mci_Wait or mci_Status_Item, DWORD(@StatusParm));
  d := StatusParm.dwReturn - 524;
  if d > 4 then
    Dec(d, 2);
  Result := WMPModes(d);
end;

function TWavViewer.GetPeaksCount: DWORD;
begin
  if FSizeData = 0 then
    Result := 0
  else
    Result := Round((Peaks.Size * Integer(Channels)) / Integer(BytesperSample));
end;

function TWavViewer.GetPosition: DWORD;
var LStatusParm : TMCI_STATUS_PARMS;
    LSendCommand: MCIERROR;
begin
  Result := 0;
  if MCIOpened then
  begin
    LStatusParm.dwItem := mci_Status_Position;
    LSendCommand       := mciSendCommand(DeviceID, mci_Status, mci_Wait or mci_Status_Item, DWORD(@LStatusParm));
    if LSendCommand = 0 then
      Result := LStatusParm.dwReturn;
  end;
end;

function TWavViewer.GetScrollPosition: Integer;
begin
  Result := GetScrollPos(Handle, SB_HORZ);
end;

function TWavViewer.GetStartPos: DWORD;
begin
  Result := MillisecondsToFormatTime(FStartPos)
end;

function TWavViewer.GetTimeFormat:WMPTimeFormats;
var
  StatusParm: TMCI_Status_Parms;
  d: DWORD;
begin
  Result := tfMilliseconds;
  if MCIOpened then
  begin
    StatusParm.dwItem := mci_Status_Time_Format;
    mciSendCommand(DeviceID, mci_Status, mci_Status_Item, DWORD(@StatusParm));
    d := StatusParm.dwReturn;
    if d > 7 then
      Dec(d, 7);
    Result := WMPTimeFormats(d);
  end;
end;

function TWavViewer.GetTrackInfo: Boolean;
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
                 
          Channels        := LWaveHeader.NumChannels;
          BytesPerSample  := LWaveHeader.BitsPerSample ;
          SamplesPerSecond:= LWaveHeader.SampleRate;
          FChunkSize      := LWaveHeader.ChunkSize;
          InfoHorz.Invalidate;
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

function TWavViewer.GetSecondoToShow: Integer;
begin
  Result := Round( FChunkSize / (SamplesPerSecond * Channels * (BytesPerSample/8)));
end;

function TWavViewer.GetTrackLength:DWORD;
begin
  Result := MillisecondsToFormatTime(Round((FSizeData / (DWORD(SamplesPerSecond) * DWORD(BytesPerSample))) * 1000));
end;

procedure TWavViewer.GoToSecond(s:Integer);
begin
  SetScrollPosition(MillisecondsToPixels(s * 1000));
end;

function TWavViewer.MillisecondsToFormatTime(ms:DWORD):DWORD;
var
  t: WMPTimeFormats;
begin
  t := GetTimeFormat;
  case t of
    tfMilliseconds  : Result := ms;
    tfBytes         : Result := Round((ms / 1000) * DWORD(SamplesPerSecond) * BytesPerSample);
  else
    Result := Round((ms / 1000) * DWORD(SamplesPerSecond));
  end;
end;

function TWavViewer.MillisecondsToPeaks(p:Integer):Integer;
begin
  if FSizeData = 0 then
    Result := 0
  else
    Result := Round(((GetPeaksCount * (p / 1000)) / ((FSizeData / BytesperSample) / DWORD(SamplesperSecond))));
end;

function TWavViewer.MillisecondsToPixels(p:Integer):Integer;
begin
  Result := PeaksToPixels(MillisecondsToPeaks(p));
end;

procedure TWavViewer.OpenMedia;
var
  OpenParm: TMCI_Open_Parms;
  FError:MCIERROR;
begin
  if not MCIOpened then
  begin
    FillChar(OpenParm, SizeOf(TMCI_Open_Parms), 0);
    OpenParm.dwCallback := 0;
    OpenParm.lpstrDeviceType := nil;
    OpenParm.lpstrElementName:=Pchar(FFileName);
    OpenParm.dwCallback := Handle;
    FError:=mciSendCommand(0,mci_Open,mci_OPEN_ELEMENT ,DWORD(@OpenParm));
    if FError <> 0 then
      MessageBox(Handle,'Media can not be open','',MB_OK)
    else
    begin
      MCIOpened := True;
      DeviceID := OpenParm.wDeviceID;
      DoPaintWindow;
    end;
  end;
end;

procedure TWavViewer.Pause;
var
  GenParm: TMCI_Generic_Parms;
begin
  if MCIOpened then
    if GetMode = mpPlaying then
    begin
      GenParm.dwCallback := 0;
      DoAutoLoop:=false;
      mciSendCommand( DeviceID, mci_Pause, mci_Wait, DWORD(@GenParm));
      KillTimer(Handle,TimerID);
    end
    else if GetMode = mpPaused then
    begin
      GenParm.dwCallback := Handle;
      DoAutoLoop:=true;
      mciSendCommand( DeviceID, mci_Resume, 0, DWORD(@GenParm));
      TimerID:=SetTimer(Handle,1,FTimerInterval,nil);
    end;
end;

function TWavViewer.PeaksToMilliseconds(p:DWORD):DWORD;
begin
  if FSizeData=0 then
    Result:=0
  else
    Result:=Round((PeaksToSamples(p) / SamplesperSecond)*1000);
end;

function TWavViewer.PeaksToPixels(p:Integer):Integer;
begin
  if FSizeData=0 then
    Result:=0
  else
    Result:=Round(p / (Integer(Channels)*2));
end;

function TWavViewer.PixelsToMilliseconds(p:Integer):Integer;
begin
  Result:=PeaksToMilliSeconds(PixelsToPeaks(p));
end;

function TWavViewer.PixelsToPeaks(p:Integer):Integer;
var
  i,j:Extended;     // avoid Overflows
  si:TScrollInfo;
begin
  i:=GetPeaksCount;
  j:=p;
  ZeroMemory(@si,sizeof(si));
  si.cbSize:=sizeof(TScrollInfo);
  si.fMask:=SIF_RANGE or SIF_PAGE;
  GetScrollInfo(Handle,SB_HORZ,si);
  Result:=Round((i*j)/((si.nMax-si.nPage)+(ClientWidth-InfoHorz.Width)));
end;

function TWavViewer.PeaksToSamples(p:DWORD):DWORD;
var
  t:DWORD;
begin
  t:=GetPeaksCount;
  if t=0 then
    Result:=0
  else
    Result:=Round(((FSizeData / Integer(BytesPerSample))*p) / t);
end;

procedure TWavViewer.Play(UseFrom:Boolean=True;StartPos:DWORD=0);
var
  PlayParm: TMCI_Play_Parms;
  Flags:DWORD;
  si:TScrollInfo;
  dp1,dp2:DWORD;
begin
  if not MCIOpened then
    OpenMedia
  else if GetMode=mpPlaying then
    exit;
  if MCIOpened then
  begin
    Flags := mci_Notify or mci_From;
    if UseFrom then
    begin
      PlayParm.dwFrom := MillisecondsToFormatTime(FStartPos);
      AutoMove:=true;
    end
    else if StartPos>0 then
      PlayParm.dwFrom := StartPos
    else
      PlayParm.dwFrom :=0;
    ZeroMemory(@si,sizeof(si));
    si.cbSize:=sizeof(TScrollInfo);
    si.fMask:=SIF_RANGE or SIF_PAGE or SIF_POS;
    GetScrollInfo(Handle,SB_HORZ,si);
    dp1:=MillisecondsToFormatTime(PixelsToMilliseconds(si.nPos));
    dp2:=dp1+MillisecondsToFormatTime(PixelsToMilliseconds(ClientWidth-InfoHorz.Width));
    if (PlayParm.dwFrom<dp1) or (PlayParm.dwFrom>dp2) then
      SetScrollPosition(Min(
        MillisecondsToPixels(FormatTimeToMilliseconds(PlayParm.dwFrom))-
        ((ClientWidth-InfoHorz.Width) div 2),si.nMax-si.nPage));
    PlayParm.dwCallback := Handle;
    if mciSendCommand( DeviceID, mci_Play, Flags, DWORD(@PlayParm))=0 then
    begin
      DoAutoLoop:=true;
      TimerID:=SetTimer(Handle,1,FTimerInterval,nil);
    end;
  end;
end;

function TWavViewer.ReadBytes(Buffer:TMemoryStream;start,sizebuffer:Integer;
  var length:Integer):Boolean;
var
  f:TFileStream;
  bread,realread:Integer;
  bProcess:boolean;
  p:Pointer;
begin
  Result:=false;
  if FSizeData=0 then exit;
  if Buffer=nil then exit;
  try
    f:=TFileStream.Create(FFileName,fmOpenRead or fmShareDenyNone);
    GetMem(p,sizebuffer);
    try
      f.Seek(start,soFromBeginning);
      bread:=0;
      bProcess:=true;
      repeat
        sizebuffer:=Min(sizebuffer,length-bread);
        realread:=f.Read(p^,sizebuffer);
        Buffer.Write(p^,realread);
        Inc(bread,realread);
        if Assigned(FOnReadBytes) then FOnReadBytes(Self,bread,bread/length,bProcess);
      until (not bProcess) or (bread>=length) or (realread<sizebuffer);
      length:=bread;
      if bread=length then
        Result:=true;
    finally
      FreeMem(p);
      f.Free;
    end;
  except
  end;
end;

function TWavViewer.ReadHeader(Buffer:Pointer):Boolean;
var f :TFileStream;
    LReadBytes :Integer;
begin
  Result :=  false;
  if FSizeData=0 then exit;
  if Buffer=nil then exit;
  
  try
    f := TFileStream.Create(FFileName,fmOpenRead or fmShareDenyNone);
    try
      LReadBytes := f.Read(Buffer^,SizeOf(TWaveHeaderNoData));
      if LReadBytes = SizeOf(TWaveHeaderNoData) then
        Result := true;
    finally
      f.Free;
    end;
  except
  end;
end;

function TWavViewer.SavePeaksToFile(FileName:TFileName=''):Boolean;
var
  f:TFileStream;
  p:array[0..4] of AnsiChar;
begin
  Result:=false;
  if FileName='' then
    FileName:=ChangeFileExt(FFileName,PeaksExt);
  try
    f:=TFileStream.Create(FileName,fmCreate or fmOpenWrite);
    try
      StrPCopy(p,'PEAK');
      f.Write(p,4);
      f.Write(BytesperSample,1);
      f.Write(Channels,1);
      f.Write(SamplesperSecond,4);
      f.Write(FSizeData,4);
      f.Write(Peaks.Memory^,Peaks.Size);
      Result:=true;
    finally
      f.Free;
    end;
  except
    MessageBox(Handle,'Invalid path or protected file','',MB_OK);
  end;
end;

procedure TWavViewer.SetBevelInner(Value:TPanelBevel);
begin
  InfoHorz.BevelInner:=Value;
  InfoHorz.Invalidate;
  InfoVert.BevelInner:=Value;
  InfoVert.Invalidate;
end;

procedure TWavViewer.SetBevelOuter(Value:TPanelBevel);
begin
  InfoHorz.BevelOuter:=Value;
  InfoHorz.Invalidate;
  InfoVert.BevelOuter:=Value;
  InfoVert.Invalidate;
end;

procedure TWavViewer.SetBevelWidth(Value:TBevelWidth);
begin
  InfoHorz.BevelWidth:=Value;
  InfoHorz.Invalidate;
  InfoVert.BevelWidth:=Value;
  InfoVert.Invalidate;
end;

procedure TWavViewer.SetBitmap(f:string);
var
  t:Integer;
begin
  FBitmap.Free;
  FBitmap:=TBitmap.Create;
  try
    FBitmap.LoadFromFile(f);
    if Peaks.Size>0 then
    begin
      t:=MillisecondsToPixels(FStartPos)-GetScrollPosition;
      if (t>0) and (t<ClientWidth) then
        DoPaintWindow;
    end;
  except
    FBitmap.Free;
  end;
end;

procedure TWavViewer.SetBorderColor(aColor:TColor);
begin
  if aColor <> FBorderColor then
  begin
    FBorderColor := aColor;
    InfoHorz.Invalidate;
    DoPaintWindow;
  end;
end;

procedure TWavViewer.SetFileName(aFilename:TFileName);
var LBckOldFile:string;
begin
  if aFilename <> FFileName then
  begin
    Peaks.Clear;
    if Trim(aFilename).IsEmpty then
    begin
      FSizeData  := 0;
      FFileName := String.Empty;
    end
    else
    begin
      LBckOldFile  := FFileName;
      FFileName    := aFilename;
      if GetTrackInfo then
      begin
        CloseMedia;
        Cursor:=crDefault;
      end
      else
        FFileName := LBckOldFile;
    end;
  end;
end;

procedure TWavViewer.SetInfoBackColor(aColor:TColor);
begin
  if aColor <> InfoHorz.Color then
  begin
    InfoHorz.Color := aColor;
    InfoVert.Color := aColor;
  end;
end;

procedure TWavViewer.SetInfoBorderWidth(aValue: TBorderWidth);
begin
  InfoHorz.BorderWidth := aValue;
  InfoHorz.Invalidate;
  InfoVert.BorderWidth := aValue;
  InfoVert.Invalidate;
end;

procedure TWavViewer.SetInfoBorderStyle(aValue: TBorderStyle);
begin
  InfoHorz.BorderStyle := aValue;
  InfoHorz.Invalidate;
  InfoVert.BorderStyle := aValue;
  InfoVert.Invalidate;
end;

procedure TWavViewer.SetInfoHeight(aHeight: Integer);
begin
  if aHeight <> InfoVert.Height then
  begin
    InfoVert.Height := aHeight;
    DoPaintWindow;
  end;
end;

procedure TWavViewer.SetInfoWidth(aWidth: Integer);
begin
  if aWidth <> InfoHorz.Width then
  begin
    InfoHorz.Width := aWidth;
    UpdateScroll;
    DoPaintWindow;
  end;
end;

procedure TWavViewer.SetLargeChange(l: Byte);
begin
  if (l > 0) and (l <> FLargeChange) and (l > FSmallChange) and (l < SecondsToShow) then
    FLargeChange := l;
end;

procedure TWavViewer.SetMarksColor(aColor:TColor);
begin
  if aColor <> FMarksColor then
  begin
    FMarksColor := aColor;
    InfoVert.Invalidate;
  end;
end;

procedure TWavViewer.SetMarksInterval(aInterval:Byte);
var LMs: DWORD;
begin
  LMs := PixelsToMilliseconds(ClientWidth-InfoHorz.Width);

  if LMs = 0 then
    LMs := ClientWidth div 5;

  if (aInterval < 2) or (aInterval > LMs) then
  begin
    if csDesigning in ComponentState then
      MessageBox(Handle,Pchar('Marks interval must be between 2 and '+IntToStr(LMs)),'',MB_OK);
    exit;
  end;
  
  if aInterval <> FMarksInterval then
  begin
    FMarksInterval := aInterval;
    InfoVert.Invalidate;
  end;
end;

procedure TWavViewer.SetPeaksExt(s: string);
begin
  if s <> PeaksExt then
  begin
    if Pos('.', s) = 0 then
      s := '.' + s;
    if System.Length(s) > 4 then
      s := Copy(s, 1, 4);
    PeaksExt := s;
  end;
end;

procedure TWavViewer.SetPeaksColor(aColor:TColor);
begin
  if aColor <> FPeaksColor then
  begin
    FPeaksColor := aColor;
    if Peaks.Size > 0 then
      DoPaintWindow;
  end;
end;

procedure TWavViewer.SetPositionColor(aColor:TColor);
var LPixel:Integer;
begin
  if aColor <> FPositionColor then
  begin
    FPositionColor := aColor;
    if Peaks.Size > 0 then
    begin
      LPixel := MillisecondsToPixels(FStartPos)-GetScrollPosition;
      if (LPixel > 0) and (LPixel < ClientWidth) then
        DoPaintWindow;
    end;
  end;
end;

procedure TWavViewer.SetPosition(p:DWORD);
var
  SeekParm: TMCI_Seek_Parms;
begin
  if MCIOpened then
  begin
    SeekParm.dwCallback := 0;
    SeekParm.dwTo := p;
    mciSendCommand( DeviceID, mci_Seek, mci_Wait or mci_To,DWORD(@SeekParm));
  end;
end;

procedure TWavViewer.SetScrollPosition(p: Integer);
begin
  if p <> GetScrollPosition then
  begin
    SetScrollPos(Handle, SB_HORZ, p, true);
    InfoVert.Invalidate;
    DoPaintWindow;
  end;
end;

procedure TWavViewer.SetSmallChange(l: Byte);
begin
  if (l > 0) and (l <> FSmallChange) and (l < FLargeChange) and (l < SecondsToShow) then
    FSmallChange := l;
end;

procedure TWavViewer.SetStartPos(p: DWORD);
var
  t: Integer;
begin
  t := FormatTimeToMilliseconds(p);
  if t <> FStartPos then
  begin
    FStartPos := t;
    if Peaks.Size > 0 then
    begin
      t := MillisecondsToPixels(FStartPos) - GetScrollPosition;
      if (t > 0) and (t < ClientWidth) then
        DoPaintWindow;
    end;
  end;
end;

procedure TWavViewer.SetTimeFormat(f: WMPTimeFormats);
var
  SetParm: TMCI_Set_Parms;
  d: DWORD;
begin
  if MCIOpened then
  begin
    d := DWORD(f);
    if d > 0 then
      Inc(d, 7);
    SetParm.dwTimeFormat := d;
    mciSendCommand(DeviceID, mci_Set, mci_Set_Time_Format, DWORD(@SetParm));
  end;
end;

procedure TWavViewer.SetTimerInterval(aInterval:Integer);
begin
  if aInterval <> FTimerInterval then
  begin
    FTimerInterval := aInterval;
    if GetMode = mpPlaying then
    begin
      KillTimer(Handle,TimerID);
      TimerID := SetTimer(Handle,1,aInterval,nil);
    end;
  end;
end;

procedure TWavViewer.Stop;
var GenParm: TMCI_Generic_Parms;
begin
  if MCIOpened then
  begin
    DoAutoLoop         := false;
    GenParm.dwCallback := 0;
    mciSendCommand( DeviceID, mci_Stop, 0, DWORD(@GenParm));
    KillTimer(Handle,TimerID);
    DoPaintWindow;
  end;
end;

procedure TWavViewer.UpdateScroll;
var LScrollInfo : TScrollInfo;
begin
  ZeroMemory(@LScrollInfo,sizeof(LScrollInfo));
  LScrollInfo.cbSize  :=  sizeof(TScrollInfo);
  LScrollInfo.fMask   :=  SIF_RANGE or SIF_POS or SIF_PAGE;
  LScrollInfo.nMin    :=  0;
  
  if Peaks.Size > 0 then
    LScrollInfo.nMax  :=  Max(PeaksToPixels(GetPeaksCount),0)
  else
    LScrollInfo.nMax  := 0;

  LScrollInfo.nPos  := 0;
  LScrollInfo.nPage := Min(LScrollInfo.nMax,ClientWidth - InfoHorz.Width);
  SetScrollInfo(Handle,SB_HORZ,LScrollInfo,true);
  InfoHorz.Invalidate;
  KillTimer(Handle,TimerID);
end;

procedure TWavViewer.WndProc(var Message:TMessage);
var
  cv:TCanvas;
  ps:TPaintStruct;
  sc:Integer;
  d,p:DWORD;
  k:Word;
  dummy:HWnd;
  dc:HDC;
begin
  case Message.Msg of
    WM_ERASEBKGND:
      begin
        {cv:=TCanvas.Create;
        cv.Handle:=HDC(Message.WParam);}
        DoPaintWindow{(true,cv)};
        //cv.Free;
        Message.Result:=1;
      end;
    WM_HSCROLL:
      begin
        DoScroll(Message.WParamLo);
        if Assigned(FOnScroll) then
        begin
          sc := Message.WParamHi;
          FOnScroll(Self, Message.WParamLo, sc);
        end;
        Message.Result := 0;
      end;
    WM_KEYDOWN:
      begin
        if not (csDesigning in ComponentState) then
        begin
          d := MillisecondsToPixels(FormatTimeToMilliseconds(FStartPos));
          p := GetScrollPosition;
          k := Message.WParam;
          if (d > p) and (d < p + (ClientWidth - InfoHorz.Width)) then
          begin
            if k = VK_RIGHT then
              Inc(FStartPos, 40)
            else if k = VK_LEFT then
              Dec(FStartPos, 40);
            Invalidate;
          end;
          inherited WndProc(Message);
          if Assigned(OnKeyDown) then
            OnKeyDown(Self, k, KeysToShiftState(Message.lParam));
          Message.Result := 0;
        end
        else
          inherited WndProc(Message);
      end;
    WM_PAINT:
      begin
        BeginPaint(Handle,ps);
        Try
          cv:=TCanvas.Create;
          Try
            cv.Handle:=ps.hdc;
            cv.Font.Assign(Font);
            cv.Brush.Color:=Color;
            cv.Brush.Style:=bsSolid;
            cv.Pen.Color:=FPeaksColor;
            DoPaintWindow(true,cv);
            if Assigned(FOnPaint) then
              FOnPaint(Self,cv);
          Finally
            cv.Free;
          End;
          
        Finally
          EndPaint(Handle,ps);
        End;
        
        Message.Result:=0;
      end;
    WM_LBUTTONDOWN:
      begin
        inherited WndProc(Message);
        Message.Result:=0;
        if (csDesigning in ComponentState) then exit;
        DoMouse(Message.LParamLo);
        SetFocus;
        if Assigned(FOnButtonDown) then
          FOnButtonDown(Self,true,Message.LParamLo,Message.LParamHi);
      end;
    WM_RBUTTONDOWN:
      begin
        inherited WndProc(Message);
        if Assigned(FOnButtonDown) then
          FOnButtonDown(Self,false,Message.LParamLo,Message.LParamHi);
        Message.Result:=0;
      end;
    MM_MCINOTIFY:
      begin
        if (FAutoLoop) and (DoAutoLoop) then
          Play;
        Message.Result:=Integer(Message.WParam<>MCI_NOTIFY_SUCCESSFUL);
      end;
    WM_SIZE:
      begin
        if MemoryCanvas<>nil then
        begin
          SelectObject(MemoryCanvas.Handle,OldBitmap);
          DeleteObject(MemoryBitmap);
          MemoryCanvas.Free;
        end;
        MemoryCanvas:=TCanvas.Create;
        dummy:=Handle;
        dc:=GetDeviceContext(dummy);
        MemoryCanvas.Handle:=CreateCompatibleDC(dc);
        MemoryBitmap:=CreateCompatibleBitmap(dc,Message.LParamLo,Message.LParamHi);
        OldBitmap:=SelectObject(MemoryCanvas.Handle,MemoryBitmap);
        InfoHorz.Constraints.MaxWidth:=Message.LParamLo-20;
        InfoVert.Constraints.MaxHeight:=Message.LParamHi-20;
        inherited WndProc(Message);
        UpdateScroll;
        Message.Result:=0;
      end;
    WM_TIMER:
      begin
        DoTimer;
        if Assigned(FOnPlaying) then
          FOnPlaying(Self,Message.WParam,GetPosition);
        Message.Result:=0;
      end;
    else
      inherited WndProc(Message);
  end;
end;

/// TMyPanel ////

procedure TMyPanel.WndProc(var Message: TMessage);
begin
  inherited WndProc(Message);

  case Message.Msg of
    WM_PAINT :
      begin
        if Tag=0 then
        begin
          TWavViewer(Parent).DoPaintHorzInfo(Canvas);
          if Assigned(TWavViewer(Parent).OnPaintHorzInfo) then
            TWavViewer(Parent).OnPaintHorzInfo(Self,Canvas);
        end
        else
        begin
          TWavViewer(Parent).DoPaintVertInfo(Canvas);
          if Assigned(TWavViewer(Parent).OnPaintVertInfo) then
            TWavViewer(Parent).OnPaintVertInfo(Self,Canvas);
        end;
        Message.Result := 0;   
      end;
    WM_SIZE :
      begin
        if Tag=0 then
          TWavViewer(Parent).Constraints.MinWidth := Message.LParamLo + 20
        else
          TWavViewer(Parent).Constraints.MinHeight := Message.LParamHi + 20;
        Message.Result := 0;      
      end;
          
  end;
end;



end.
