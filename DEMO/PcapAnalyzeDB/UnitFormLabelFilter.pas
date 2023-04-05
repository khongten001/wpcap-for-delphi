unit UnitFormLabelFilter;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, cxGraphics, cxControls, cxLookAndFeels,
  cxLookAndFeelPainters, dxSkinsCore, dxSkinBasic, cxCustomData, cxStyles,
  dxScrollbarAnnotations, cxTL, cxTLdxBarBuiltInMenu, cxInplaceContainer,
  cxTLData, cxDBTL, Data.DB, cxMaskEdit, cxMemo;

type
  TFormLabelFilter = class(TForm)
    cxDBTreeList1: TcxDBTreeList;
    DsList: TDataSource;
    cxDBTreeList1cxDBTreeListColumn1: TcxDBTreeListColumn;
    cxDBTreeList1cxDBTreeListColumn2: TcxDBTreeListColumn;
    procedure cxDBTreeList1DblClick(Sender: TObject);
  private
    { Private declarations }
    FSelectLabel : String;
  public
    { Public declarations }
    property SelectLabel: String read FSelectLabel;
  end;



implementation

{$R *.dfm}

procedure TFormLabelFilter.cxDBTreeList1DblClick(Sender: TObject);
begin
  if Assigned(cxDBTreeList1.FocusedNode) then
  begin
    FSelectLabel := cxDBTreeList1.FocusedNode.Values[cxDBTreeList1cxDBTreeListColumn1.Position.ColIndex];
    ModalResult := mrOK;
    
  end;
end;

end.
