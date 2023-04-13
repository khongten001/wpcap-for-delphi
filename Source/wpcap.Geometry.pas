//*************************************************************
//                        WPCAP FOR DELPHI                    *
//				                                        			      *
//                     Freeware Library                       *
//                       For Delphi 10.4                      *
//                            by                              *
//                     Alessandro Mancini                     *
//				                                        			      *
//*************************************************************
{LICENSE:
THIS SOFTWARE IS PROVIDED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESSED OR IMPLIED INCLUDING BUT NOT LIMITED TO THE APPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
YOU ASSUME THE ENTIRE RISK AS TO THE ACCURACY AND THE USE OF THE SOFTWARE
AND ALL OTHER RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SOFTWARE
AND DOCUMENTATION. PRODUCTIONS DOES NOT WARRANT THAT THE SOFTWARE IS ERROR-FREE
OR WILL OPERATE WITHOUT INTERRUPTION. THE SOFTWARE IS NOT DESIGNED, INTENDED
OR LICENSED FOR USE IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE CONTROLS,
INCLUDING WITHOUT LIMITATION, THE DESIGN, CONSTRUCTION, MAINTENANCE OR
OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR COMMUNICATION SYSTEMS,
AIR TRAFFIC CONTROL, AND LIFE SUPPORT OR WEAPONS SYSTEMS. PRODUCTIONS SPECIFICALLY
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR SUCH PURPOSE.

You may use/change/modify the component under 1 conditions:
1. In your application, add credits to "WPCAP FOR DELPHI"
{*******************************************************************************}

unit wpcap.Geometry;

interface

uses System.Math,System.Generics.Collections;

CONST EARTH_RADIUS = 6371; // Earth's radius in km

type
  TMapCoordinate = record
  private
    FLatitude : Double;
    FLongitude: Double;
    FInfo     : string;
    FDateTime : TDateTime;
  public
    function DistanceTo(const AOther: TMapCoordinate): Double;
    property Latitude : Double    read FLatitude   write FLatitude;
    property Longitude: Double    read FLongitude  write FLongitude;
    property Info     : String    read FInfo       write FInfo;    
    property DateTime : TDateTime read FDateTime   write FDateTime;    
  end;

  PTMapCoordinate = ^TMapCoordinate;
  TListCoordinate  = Class(TList<PTMapCoordinate>);
  

function GreatCircle(const aLat1, aLon1, aLat2, aLon2: Double): TListCoordinate;

implementation


function TMapCoordinate.DistanceTo(const AOther: TMapCoordinate): Double;
var LDeltaLat : Double; 
    LDeltaLon : Double; 
    A         : Double;
    C         : Double;
begin
  LDeltaLat := (AOther.Latitude - FLatitude) * PI / 180;
  LDeltaLon := (AOther.Longitude - FLongitude) * PI / 180;
  A         := Sin(LDeltaLat/2) * Sin(LDeltaLat/2) +
               Cos(FLatitude * PI / 180) * Cos(AOther.Latitude * PI / 180) *
               Sin(LDeltaLon/2) * Sin(LDeltaLon/2);
  C         := 2 * ArcTan2(Sqrt(A), Sqrt(1-A));
  Result    := EARTH_RADIUS * C;
end;


function GreatCircle(const aLat1, aLon1, aLat2, aLon2: Double): TListCoordinate;
CONST TOL = 1e-10;
var LLat1       : Double; 
    LLon1       : Double; 
    LLat2       : Double; 
    LLon2       : Double; 
    LCoordinate : PTMapCoordinate;
    LArc        : Double;
    LNewLat     : Double;
    LNewLon     : Double;    
    LEndLon     : Double;
begin
  Result := TListCoordinate.Create;
  // Convert incoming coordinates to radians
  LLat1   := DegToRad(aLat1);
  LLon1   := DegToRad(aLon1);
  LLat2   := DegToRad(aLat2);
  LLon2   := DegToRad(aLon2);

  LArc    := PI / 180.0; // Size of increments in radians
  LNewLon := Min(LLon1, LLon2);
  
  if Abs(LLon1 - LLon2) <= TOL then
    LLon2 := LNewLon + PI; // Avoid 'divide by zero' error in following eq.

  // If longitudes and latitudes are each 180 degrees apart then
  // tweak one lat by a millionth of a degree to avoid ambiguity in cross-polar route
  if Abs(LLon2 - LLon1) = PI then
  begin
    if LLat1 + LLat2 = 0.0 then
      LLat2 := LLat2 + PI / 180000000;
  end;

  LNewLon := DegToRad(aLon1);
  LEndLon := DegToRad(aLon2);

  while LNewLon <= LEndLon do
  begin
    LNewLat := ArcTan((Sin(LLat1) * Cos(LLat2) * Sin(LNewLon - LLon2)- Sin(LLat2) * Cos(LLat1) * Sin(LNewLon - LLon1)) / (Cos(LLat1) * Cos(LLat2) * Sin(LLon1 - LLon2)));

    New(LCoordinate);
    LCoordinate.Latitude  := RadToDeg(LNewLat); 
    LCoordinate.Longitude := RadToDeg(LNewLon);
    Result.Add(LCoordinate);
    
    if (LNewLon < LEndLon) and ((LNewLon + LArc) >= LEndLon) then
      LNewLon := LEndLon
    else
      LNewLon := LNewLon + LArc;
  end;

end;



end.
