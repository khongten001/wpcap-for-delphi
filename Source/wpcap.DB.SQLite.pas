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

unit wpcap.DB.SQLite;

interface

uses
  wpcap.DB.Base, System.Classes, FireDAC.Phys, FireDAC.Phys.SQLite,
  System.SysUtils;

type
  /// <summary>
  /// The TWPcapDBSqLite class extends the TWPcapDBBase class and implements a database
  /// connection to SQLite. It provides methods to open and close the connection,
  /// and to execute SQL queries and commands. This class is used to write and read
  /// data from SQLite database files that store packets captured using
  /// the WinPcap library.
  /// </summary>

  TWPcapDBSqLite = Class(TWPcapDBBase)
  Strict private
    var FDriverLink : TFDPhysSQLiteDriverLink;   

  protected

    procedure InsertVersion;virtual;     
  
    procedure CreateFDDriverLink;override;
    procedure InsertMetadata(const aName: String; aValue: String);override;       
    function GetDriverIDName:String;override;
    procedure DestroyFDDriverLink;override;  
    procedure SetCredentialConnection(const aUsername,aPassword:String); override;    
    procedure SetTNSConnection(const aTNS:String); override;       
  End;

implementation

{ TDBSqLite }
procedure TWPcapDBSqLite.CreateFDDriverLink;
begin
  FDriverLink := TFDPhysSQLiteDriverLink.Create( nil );
end;

function TWPcapDBSqLite.GetDriverIDName: String;
begin
  Result := 'SQLite';
end;

procedure TWPcapDBSqLite.DestroyFDDriverLink;
begin
  FreeAndNIl(FDriverLink);
end;

procedure TWPcapDBSqLite.SetCredentialConnection(const aUsername,aPassword: String);
begin
  //
end;

procedure TWPcapDBSqLite.SetTNSConnection(const aTNS: String);
begin
  //

end;

procedure TWPcapDBSqLite.InsertVersion;
begin

end;

procedure TWPcapDBSqLite.InsertMetadata(const aName: String; aValue: String);
begin
  
end;

end.
