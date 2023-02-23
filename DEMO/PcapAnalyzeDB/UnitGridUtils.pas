unit UnitGridUtils;

interface
uses
  Windows, Classes, cxGrid, Forms, cxGridDBBandedTableView, cxGridCustomView,
  cxGridDBTableView, SysUtils, Variants, clipbrd, Dialogs, cxGridExportLink,
  cxVGrid,cxTL,cxTLExportLink;

type
    TFilterDialog = record
    FilterDescription : String;
    Extension         : string;
    IndexFilter       : Integer;
  end;
  
Const
  {indice su save dialog}
  INDEX_SAVE_XLS     = 1;
  INDEX_SAVE_HTML    = 2;
  INDEX_SAVE_TXT     = 3;
  INDEX_SAVE_XML     = 4;
  INDEX_SAVE_XLSX    = 5;
  {Estensione}
  EXT_SAVE_XLS       = '.xls';
  EXT_SAVE_HTML      = '.html';
  EXT_SAVE_TXT       = '.txt';
  EXT_SAVE_XML       = '.xml';
  EXT_SAVE_XLSX      = '.xlsx';
  {Descrizione}
  CAPTOIN_SAVE_XLS   = 'MS Excel 2003 *'+EXT_SAVE_XLS;
  CAPTOIN_SAVE_HTML  = 'Web page *'+EXT_SAVE_HTML;
  CAPTOIN_SAVE_TXT   = 'Text file *'+EXT_SAVE_TXT;
  CAPTOIN_SAVE_XML   = 'XML file *'+EXT_SAVE_XML;
  CAPTOIN_SAVE_XLSX  = 'MS Excel 2007 *'+EXT_SAVE_XLSX;

  FilterArrayValue : array[1..5] of TFilterDialog = (
    ( FilterDescription : CAPTOIN_SAVE_XLS;  Extension : EXT_SAVE_XLS;  IndexFilter : INDEX_SAVE_XLS ),
    ( FilterDescription : CAPTOIN_SAVE_HTML; Extension : EXT_SAVE_HTML; IndexFilter : INDEX_SAVE_HTML ),
    ( FilterDescription : CAPTOIN_SAVE_TXT;  Extension : EXT_SAVE_TXT;  IndexFilter : INDEX_SAVE_TXT ),
    ( FilterDescription : CAPTOIN_SAVE_XML;  Extension : EXT_SAVE_XML;  IndexFilter : INDEX_SAVE_XML ),
    ( FilterDescription : CAPTOIN_SAVE_XLSX; Extension : EXT_SAVE_XLSX; IndexFilter : INDEX_SAVE_XLSX )
  ) ;


  function GetCellCaption(aGridView:TcxCustomGridView):string;overload;
  function GetCellCaption(aGrid:TcxVerticalGrid):string;overload;
  function GetCellValue(aGridView:TcxCustomGridView):string;overload;
  function GetCellValue(aGrid:TcxCustomVerticalGrid):string;overload;
  procedure CopyCellValue(aGridView:TcxCustomGridView);overload;
  procedure CopyCellValue(aGrid:TcxVerticalGrid);overload;
  procedure CopyCellValue(aGrid:TcxCustomVerticalGrid);overload;
  procedure CopyColumnValues(aGridView:TcxCustomGridView);
  procedure CopyRecord(aGridView:TcxCustomGridView);overload;
  procedure CopyRecord(aGrid:TcxVerticalGrid);overload;
  procedure SaveList(aList:TcxCustomTreeList;aSaveDialog: TSaveDialog);

  procedure SaveGrid(aGrid:TCxGrid;aSaveDialog:TSaveDialog);

implementation

uses
  cxGridCustomTableView, cxGridCardView, cxGridTableView;

var LastFolderExport : string;

function GetCellCaption(aGrid:TcxVerticalGrid):string;overload;
begin
  Result := '';
  if not Assigned(aGrid.FocusedRow) then Exit;
  if not (aGrid.FocusedRow is TcxEditorRow) then Exit;
  Result  := TcxEditorRow(aGrid.FocusedRow).Properties.Caption;
end;

function GetCellCaption(aGridView:TcxCustomGridView):string;
var TableView : TcxGridDBTableView;
begin
  result := '';
  if aGridView is TcxGridDBTableView then
  begin
    TableView := (aGridView as TcxGridDBTableView);
    with TableView.Controller do
    begin
      if TableView.OptionsSelection.CellSelect then
      begin
        if not Assigned(FocusedColumn) then
        begin
          MessageBox(0, PChar('No column selected !'), PChar('Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          exit;
        end;

        if not Assigned(FocusedRow) then
        begin
          MessageBox(0, PChar('No row selected !'), PChar( 'Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          exit;
        end;
        result    := FocusedRow.GridView.Columns[FocusedColumn.Index].Caption
      end;
    end;
  end;
end;

function GetCellValue(aGridView:TcxCustomGridView):string;
var TableDBView  : TcxGridDBTableView;
    TableView    : TcxGridTableView;
    TableView2   : TcxGridDBBandedTableView;
begin
  result := '';

  if aGridView is TcxGridDBTableView then
  begin
    TableDBView := (aGridView as TcxGridDBTableView);
    with TableDBView.Controller do
    begin
      if TableDBView.OptionsSelection.CellSelect then
      begin
        if not Assigned(FocusedColumn) then
        begin
          MessageBox(0, PChar('No column selected !'), PChar('Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          exit;
        end;

        if not Assigned(FocusedRow) then
        begin
          MessageBox(0, PChar('No row selected !'), PChar( 'Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          exit;
        end;

        result    := TableDBView.DataController.DisplayTexts[TableDBView.DataController.FocusedRecordIndex,FocusedColumn.Index];
      end;
    end;
  end;

  if aGridView is TcxGridTableView then
  begin
    TableView := (aGridView as TcxGridTableView);
    with TableView.Controller do
    begin
      if TableView.OptionsSelection.CellSelect then
      begin
        if not Assigned(FocusedColumn) then
        begin
          MessageBox(0, PChar('No column selected !'), PChar('Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          exit;
        end;

        if not Assigned(FocusedRow) then
        begin
          MessageBox(0, PChar('No row selected !'), PChar( 'Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          exit;
        end;

        result    := TableView.DataController.DisplayTexts[TableView.DataController.FocusedRecordIndex,FocusedColumn.Index];
      end;
    end;
  end;

  if aGridView is TcxGridDBBandedTableView then
  begin
    TableView2 := (aGridView as TcxGridDBBandedTableView);
    with TableView2.Controller do
    begin
      if TableView2.OptionsSelection.CellSelect then
      begin
        FocusedRecordIndex := TableView2.DataController.FocusedRecordIndex;
        Result             := TableView2.DataController.DisplayTexts[FocusedRecordIndex,FocusedColumn.Index];
      end;
    end;
  end;
end;

procedure CopyCellValue(aGridView:TcxCustomGridView);
begin
  Clipboard.AsText :=  GetCellValue(aGridView);
end;

procedure CopyRecord(aGridView:TcxCustomGridView);
var
    Lista : TStringList;
    TableView : TcxGridDBTableView;
    TableView2 : TcxGridDBBandedTableView;
    i : Integer;
    Y : Integer;
    Value : string;
    Nome : string;
    ListaCampi : string;
    NameValue : string;
    FocusedRecordIndex : Integer;
begin

  if aGridView is TcxGridDBTableView then
  begin
    TableView := (aGridView as TcxGridDBTableView);
    Lista := TStringList.Create;
    try
      for I := 0 to TableView.ColumnCount - 1 do
      begin
        NameValue :=  '';
        if not TableView.Columns[i].Visible then
        begin
          //AM: R04043 Procedimento e decreto vengono sempre mostrati
          if ( (TableView.Columns[I].DataBinding.FieldName <> 'NOMEDECRETO')
            and (TableView.Columns[I].DataBinding.FieldName <> 'NOMEPROCEDIMENTO') ) then
            Continue;
        end;

        if TableView.Columns[i].tag > 0 then
          Continue;

        FocusedRecordIndex := TableView.DataController.FocusedRecordIndex;

        Nome  := TableView.Columns[i].Caption;
        Value := TableView.DataController.DisplayTexts[FocusedRecordIndex,i];

        if Nome <> '' then
        begin
          NameValue := Format('%s = %s',[Nome,Value]);
          Lista.Add(NameValue);
        end;
      end;

      Clipboard.AsText := Lista.Text;
    finally
      Lista.Free;
    end;
  end;

  if aGridView is TcxGridDBBandedTableView then
  begin
    TableView2 := (aGridView as TcxGridDBBandedTableView);
    Lista := TStringList.Create;
    try
      for y := 0 to TableView2.Controller.SelectedRowCount -1 do
        begin
          NameValue  := '';
          ListaCampi := '';
          for I := 0 to TableView2.ColumnCount - 1 do
          begin
            if not TableView2.Columns[i].Visible then
              Continue;

            Nome  := TableView2.Columns[i].Caption;
            Value := TableView2.Controller.SelectedRows[y].DisplayTexts[i];

            if TableView2.Controller.SelectedRowCount <= 1 then
              begin
                NameValue := Format('%s = %s',[Nome,Value]);
                Lista.Add(NameValue)
              end
            else
              begin
                if y = 0 then
                  begin
                    if ListaCampi = '' then
                      ListaCampi := Nome
                    else
                      ListaCampi := ListaCampi + ';' + Nome
                  end;

                if NameValue = '' then
                  NameValue := Value
                else
                  NameValue := NameValue + ';' + Value;
              end;
          end;

          if TableView2.Controller.SelectedRowCount > 1 then
            begin
              if y = 0 then
                Lista.Add(ListaCampi);

              Lista.Add(NameValue)
            end;
        end;

      Clipboard.AsText := Lista.Text;
    finally
      Lista.Free;
    end;
  end;
end;

procedure SetFilterSaveDialog(aSaveDialog:TSaveDialog);
var FilterValue      : TFilterDialog;
begin
  {*.xls (MS Excel)|*.xls|*.html (Pagina web)|*.html|*.txt (Testo)|*.txt|*.xml (XML)|*.xml|*.xlsx ( MS Excel > 2007 )|*.xlsx}
  aSaveDialog.InitialDir := LastFolderExport;
  aSaveDialog.Filter     := '';
  for FilterValue in FilterArrayValue do
    if aSaveDialog.Filter = '' then
      aSaveDialog.Filter := Format('%s|*%s',[FilterValue.FilterDescription,FilterValue.Extension])
    else
      aSaveDialog.Filter := Format('%s|%s|*%s',[aSaveDialog.Filter,FilterValue.FilterDescription,FilterValue.Extension]);
end;

procedure SaveGrid(aGrid:TCxGrid;aSaveDialog: TSaveDialog);
begin
  SetFilterSaveDialog(aSaveDialog);

  if aSaveDialog.Execute then
  begin
    LastFolderExport := ExtractFilePath(aSaveDialog.FileName);
    case aSaveDialog.FilterIndex of
      INDEX_SAVE_XLS  : ExportGridToExcel(aSaveDialog.FileName,aGrid,False);
      INDEX_SAVE_HTML : ExportGridToHTML(aSaveDialog.FileName,aGrid,False);
      INDEX_SAVE_TXT  : ExportGridToText(aSaveDialog.FileName,aGrid,False);
      INDEX_SAVE_XML  : ExportGridToXML(aSaveDialog.FileName,aGrid,False);
      INDEX_SAVE_XLSX : ExportGridToXLSX(aSaveDialog.FileName,aGrid,False);
    else
      begin
        MessageBox(0,PChar('Export format not supported'), PChar('Errore'), MB_ICONERROR or MB_OK or MB_TASKMODAL or MB_TOPMOST);
      end;
    end;

  end;
end;

procedure SaveList(aList:TcxCustomTreeList;aSaveDialog: TSaveDialog);
begin
  SetFilterSaveDialog(aSaveDialog);

  if aSaveDialog.Execute then
  begin
    LastFolderExport := ExtractFilePath(aSaveDialog.FileName);
    case aSaveDialog.FilterIndex of
      INDEX_SAVE_XLS  : cxExportTLToExcel(aSaveDialog.FileName,aList);
      INDEX_SAVE_HTML : cxExportTLToHTML(aSaveDialog.FileName,aList);
      INDEX_SAVE_TXT  : cxExportTLToCSV(aSaveDialog.FileName,aList);
      INDEX_SAVE_XML  : cxExportTLToXML(aSaveDialog.FileName,aList);
      INDEX_SAVE_XLSX : cxExportTLToXLSX(aSaveDialog.FileName,aList);
    else
      begin
        MessageBox(0,PChar('Export format not supported'), PChar('Errore'), MB_ICONERROR or MB_OK or MB_TASKMODAL or MB_TOPMOST);
      end;
    end;

  end;
end;


procedure CopyColumnValues(aGridView:TcxCustomGridView);

const COLUMNVALUES_SEPARATOR = ';' + sLineBreak;

  var
    TableView : TcxGridDBTableView;
    Value : string;
    OutValue : string;
    Title : string;
    Colum : TcxGridDBColumn;
begin
  if aGridView is TcxGridDBTableView then
  begin
    TableView := (aGridView as TcxGridDBTableView);
    with TableView.Controller do
    begin
      if TableView.OptionsSelection.CellSelect then
      begin
        if not Assigned(FocusedColumn) then
        begin
          MessageBox(0, PChar( 'No column selected !'), PChar('Information'), MB_ICONINFORMATION or MB_OK or MB_TASKMODAL or MB_TOPMOST);
          Exit;
        end;
        //AM: R04042 -[INT-AG] - Terminale : Errore in copia valore colonna
        TableView.DataController.DataSource.DataSet.First;
        Colum  := TableView.Columns[FocusedColumn.Index];
        while not TableView.DataController.DataSource.DataSet.Eof do
        begin
          Value := TableView.DataController.DataSource.DataSet.FieldByName(Colum.DataBinding.FieldName).AsString;

          Title := FocusedColumn.Caption;
          if OutValue = '' then
            OutValue := Format('%s%s%s',[Title,sLineBreak,Value])
          else
            OutValue := OutValue + COLUMNVALUES_SEPARATOR + Value;
          TableView.DataController.DataSource.DataSet.Next;
        end;
        Clipboard.AsText := OutValue;
      end;
    end;
  end;
end;

procedure CopyRecord(aGrid:TcxVerticalGrid);
  var
    I: Integer;
  var
    Lista : TStringList;
    Value : variant;
    ValueStr : string;
    Nome : string;
    NameValue : string;
    Prop : TcxEditorRowProperties;
begin
  Lista := TStringList.Create;
  try
    for I := 0 to aGrid.Rows.Count - 1 do
    begin
      if not aGrid.Rows[i].Visible then
        Continue;

      if aGrid.Rows[i].Tag > 0 then
        Continue;

      if not (aGrid.Rows[i] is TcxEditorRow) then
        Continue;

      Nome  := TcxEditorRow(aGrid.Rows[i]).Properties.Caption;

      Prop := TcxEditorRow(aGrid.Rows[i]).Properties;
      Value := Prop.DisplayEditProperties[0].GetDisplayText(Prop.Value);

      ValueStr := VarToStrDef(Value,'');

      if Nome <> '' then
      begin
        NameValue := Format('%s = %s',[Nome,ValueStr]);
        Lista.Add(NameValue);
      end;
    end;

    Clipboard.AsText := Lista.Text;
  finally
    Lista.Free;
  end;
end;

procedure CopyCellValue(aGrid:TcxVerticalGrid);overload;
begin
  Clipboard.AsText := GetCellValue(aGrid);
end;

procedure CopyCellValue(aGrid:TcxCustomVerticalGrid);overload;
begin
  Clipboard.AsText := GetCellValue(aGrid);
end;

function GetCellValue(aGrid:TcxCustomVerticalGrid):string;
  var
    Prop : TcxEditorRowProperties;
    Value : variant;
    ValueStr : string;
begin
  Result := '';
  if not Assigned(aGrid.FocusedRow) then
    Exit;

  if not (aGrid.FocusedRow is TcxEditorRow) then
    Exit;

  Prop := TcxEditorRow(aGrid.FocusedRow).Properties;

  Value := Prop.DisplayEditProperties[0].GetDisplayText(Prop.Value);
  ValueStr := VarToStrDef(Value,'');

  result := ValueStr;
end;



end.
