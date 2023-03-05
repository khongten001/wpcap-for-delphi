unit UnFormMap;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, cxGraphics,
  cxControls, cxLookAndFeels, cxLookAndFeelPainters, dxSkinsCore, dxSkinBasic,
  dxMapControlTypes, dxMapItem, dxMapControl,
  dxMapControlOpenStreetMapImageryDataProvider, System.Generics.Collections,
  dxCustomMapItemLayer, dxMapItemLayer, cxClasses, dxMapLayer, dxCoreGraphics,
  cxGeometry, dxMapImageTileLayer, cxContainer, cxEdit, dxGDIPlusClasses,
  cxImage,Wpcap.Geometry;

type

  TdxMapPushpinAccess = class (TdxMapPushpin);
  
  TFormMap = class(TForm)
    dxMapControl1: TdxMapControl;
    dxMapControl1ImageTileLayer1: TdxMapImageTileLayer;
    dxMapControl1ItemLayer1: TdxMapItemLayer;
    ImgCell: TcxImage;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormCreate(Sender: TObject);
  private
    FCurrentCoordinates : TListCoordinate; 
    procedure ClearLayer;

    function getCoordinatesCount: Integer;
    procedure ZoomCurrentCoodinates;
    function GetHitCoordinates(const aInfo: String): String;
    procedure AddMarker(Lat, lng: extended; const Info: String; Img: TcxImage);
    procedure DrawLinePath(aCoordinate:TListCoordinate;aColor: TColor);
    procedure CenterMap(lat, lng: extended; Zoom: Smallint);
    { Private declarations }
  public
    { Public declarations }
    Property CurrentCoordinates : TListCoordinate read FCurrentCoordinates; 
    procedure DrawGeoIP(aClearLayer, aAutoZoom: Boolean);
  end;


implementation

{$R *.dfm}

function TFormMap.getCoordinatesCount: Integer;
begin
  Result := FCurrentCoordinates.Count;
end;


procedure TFormMap.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caHide;
end;

procedure TFormMap.DrawLinePath(aCoordinate:TListCoordinate;aColor:TColor);
CONST  WIDTH_PATH = 5;
var LPath : TdxMapPolyline;
    i     : Integer;
    LPoint: TdxMapControlGeoPointItem;
    LItem : TdxMapItem;
begin
  LItem                           := dxMapControl1ItemLayer1.MapItems.Add(TdxMapPolyline);

  LItem.Style.BorderColor         := dxColorToAlphaColor(aColor);
  LItem.Style.BorderWidth         := WIDTH_PATH;
  LItem.Style.Color               := dxColorToAlphaColor(aColor);
  LItem.StyleHot.BorderColor      := dxColorToAlphaColor(aColor);
  LItem.StyleHot.BorderWidth      := WIDTH_PATH;
  LItem.StyleHot.Color            := dxColorToAlphaColor(aColor);
  LItem.StyleSelected.BorderColor := dxColorToAlphaColor(aColor);
  LItem.StyleSelected.BorderWidth := WIDTH_PATH;
  LItem.StyleSelected.Color       := dxColorToAlphaColor(aColor);

  LPath                           := TdxMapPolyline(LItem);
  for I := 0 to aCoordinate.Count -1 do
  begin
    LPoint           := LPath.GeoPoints.Add;
    LPoint.Latitude  := aCoordinate[I].latitude;
    LPoint.Longitude := aCoordinate[I].Longitude;
  end;

end;

Procedure TFormMap.AddMarker(Lat,lng:extended;Const Info:String;Img:TcxImage);
var LItem  : TdxMapPushpin;
begin
  LItem                    := dxMapControl1ItemLayer1.AddItem(TdxMapPushpin) as TdxMapPushpin;
  LItem.Location.Latitude  := Lat;
  LItem.Location.Longitude := Lng;
  LItem.Hint               := Info;
  TdxMapPushpinAccess(LItem).Image.Assign(Img.Picture.Graphic as TdxSmartImage);
end;


procedure TFormMap.DrawGeoIP(aClearLayer, aAutoZoom: Boolean);
var i            : integer;
    LGreatCircle : TListCoordinate;
begin
  dxMapControl1ItemLayer1.MapItems.BeginUpdate;
  Try
    if aClearLayer then
      ClearLayer;


    if FCurrentCoordinates.Count > 1 then    
    begin
      LGreatCircle := GreatCircle(FCurrentCoordinates[0].latitude,FCurrentCoordinates[0].Longitude,FCurrentCoordinates[1].latitude,FCurrentCoordinates[1].Longitude) ;
      Try  
        DrawLinePath(LGreatCircle,$00334CCC);
      finally
        FreeAndNil(LGreatCircle);
      End;
    end;
    for I := 0 to FCurrentCoordinates.Count -1 do
      AddMarker(FCurrentCoordinates[I].latitude,FCurrentCoordinates[I].Longitude,GetHitCoordinates(FCurrentCoordinates[I].Info),ImgCell);

  Finally
    dxMapControl1ItemLayer1.MapItems.EndUpdate();
  End;
  if aAutoZoom then
    ZoomCurrentCoodinates;
end;

Function TFormMap.GetHitCoordinates(const aInfo:String):String;
var LList : TArray<String>;
    I     : Integer;
begin
  Result := aInfo;
  if Pos(';',result) > 0 then
  begin
    LList := Result.Split([';']);
    Try
      Result := String.Empty;
      for I := Low(LList) to High(LList) do
      begin
        if LList[I].Trim.IsEmpty then Continue;

        if Result.IsEmpty then
          Result := LList[I]
        else
          Result := Format('%s%s%s',[Result,sLineBreak,LList[I].Trim])
      end;
    Finally
      SetLength(LList,0);
    End;
  end;
end;

Procedure TFormMap.ZoomCurrentCoodinates;
var LList     : TdxCustomMapItemLayerList;
    LBarHeight: Double;
begin
  if dxMapControl1ItemLayer1.MapItems.Count  > 1 then
  begin


    LList := TdxCustomMapItemLayerList.Create;
    try
      LList.Add(dxMapControl1ItemLayer1);
      LBarHeight := dxMapControl1.NavigationPanel.Height / dxMapControl1.Height * 2;
      dxMapControl1.ZoomToFitLayerItems(LList, LBarHeight);
    finally
      LList.Free;
    end;
  end
  else if getCoordinatesCount = 1 then
    CenterMap(FCurrentCoordinates[0].latitude,FCurrentCoordinates[0].Longitude,15);
end;

Procedure TFormMap.CenterMap(lat,lng:extended;Zoom:Smallint);
begin
  dxMapControl1.CenterPoint.Longitude := lng;
  dxMapControl1.CenterPoint.Latitude  := lat;
  if Zoom > 0 then
    dxMapControl1.ZoomAsync(Zoom);
end;

Procedure TFormMap.ClearLayer;
begin
  dxMapControl1ItemLayer1.MapItems.Clear;
  dxMapControl1.CenterPoint.Longitude := 0;
  dxMapControl1.CenterPoint.Longitude := 0;
  dxMapControl1.ZoomLevel             := 0;
end;

procedure TFormMap.FormCreate(Sender: TObject);
begin
  FCurrentCoordinates := TListCoordinate.Create;
end;

end.
