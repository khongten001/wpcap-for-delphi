unit wpcap.Logger;

interface
uses
  WinApi.Windows, WinApi.Messages, System.SysUtils, System.Classes, vcl.Graphics,
  vcl.Controls, vcl.Forms, vcl.FileCtrl, vcl.Dialogs, WinApi.PsAPI,
  System.AnsiStrings, System.IOUtils,wpcap.Types;

const
  TIME_MINUTE                   = (1000 * 60); {One minut}
  DELTA_TIMER_CHECK             = (30 * TIME_MINUTE);

  MSG_TO_THLOG_LOG              = WM_USER + 2; // Used for logging a message in the THLog thread.
  MSG_TO_THLOG_START_TIMER_SVE  = WM_USER + 3; // Used for starting the timer to save the log in the THLog thread.
  MSG_TO_THLOG_STOP_TIMER_SVE   = WM_USER + 4; // Used for stopping the timer to save the log in the THLog thread.
  MSG_TO_THLOG_START_TIMER_INFO = WM_USER + 5; // Used for starting the timer to collect memory usage information in the THLog thread.
  MSG_TO_THLOG_STOP_TIMER_INFO  = WM_USER + 6; // Used for stopping the timer to collect memory usage information in the THLog thread.
  MSG_TO_THLOG_KILL             = WM_USER + 7; // Used for terminating the THLog thread.
  MSG_TO_THLOG_STOP             = WM_USER + 8; // Used for stopping the THLog thread.

  EXTENSION			 	 :AnsiString	= '.txt';   // File extension for log files.
  PREFIX_FILE_LOG  :AnsiString  = '_LOG_';  // Prefix added to the log file name.
  GLOBAL_FILE_NAME :AnsiString	= 'Global'; // Name of the global log file.

  MAX_LEN_LEVEL_NAME           	= 11;

  B  = 1; //byte
  KB = 1024 * B; //kilobyte
  MB = 1024 * KB; //megabyte
  GB = 1024 * MB; //gigabyte

type
  TWpcapLogger  = class;

  /// <summary>
  /// A procedure type used to handle error events.
  /// <para>aFunction: The name of the function where the error occurred.</para>
  /// <para>aError: The error message.</para>
  /// </summary>
  TEvError = procedure(aFunction: AnsiString; aError: AnsiString) of object;

  /// <summary>
  /// A procedure type used to handle informational events.
  /// <para>IdtCns: An identifier for the event.</para>
  /// <para>aDateTimeEvent: The date and time of the event.</para>
  /// <para>aFunction: The name of the function where the event occurred.</para>
  /// <para>aTextInfo: Additional information about the event.</para>
  /// </summary>
  TEvInfo = procedure(IdtCns: Integer; aDateTimeEvent: TDateTime; aFunction: AnsiString; aTextInfo: AnsiString) of object;

  /// <summary>
  /// A record representing a log message.
  /// </summary>  
  MsgLog  = packed record
    Level         : TWpcapLvlLog;
    ErrorCode     : Integer;
    FunctionName  : AnsiString;
    Description   : AnsiString;
    TabCount      : Integer;
  end;
  
  /// <summary>
  /// A pointer to a MsgLog record.
  /// </summary>
  pMsgLog = ^MsgLog;
  
  /// <summary>
  /// A class that provides information about memory usage and allocation.
  /// </summary>
  TInfoMemory = class(TPersistent)
    constructor Create(ThLogId : Integer);   // Creates a new TInfoMemory object with the given ThLogId.
  private
    FThLogId          : Integer;   // The ID of the thread that created the TInfoMemory object.
    FEnableInfoMemory : Boolean;   // Whether or not information about memory usage should be stored.
    FInterval         : Integer;   // The interval (in minutes) between memory usage snapshots.
    
    /// <summary>
    /// Sets the EnableInfoMemory property to the given value.
    /// </summary>
    procedure SetEnableInfoMemory(aValue : boolean);   
    
    /// <summary>
    /// Sets the Interval property to the given value.
    /// </summary>    
    procedure SetInfoMemoryInterval(aValue : integer);    
  published
    /// <summary>
    /// Whether or not information about memory usage should be stored.
    /// </summary>    
    property EnableInfoMemory   : boolean read FEnableInfoMemory    write SetEnableInfoMemory   stored true;   
    
    /// <summary>
    ///  The interval (in minutes) between memory usage snapshots.
    /// </summary>    
    property MinutiIntervallo   : integer read FInterval            write SetInfoMemoryInterval Default 60;   
  end;


  /// <summary>
  /// Represents a thread object used for logging in the TWpcapLogger class.
  /// </summary>
  TThreadLog = class(TThread)
  private
    FEventStart              : THandle;            // The handle of the event used to start the thread.
    FParentClass             : TWpcapLogger;       // A reference to the parent TWpcapLogger object.
    FTimerDeleteLog          : NativeUInt;         // A timer used for deleting old log files.
    FTimerInfoMemory         : NativeUInt;         // A timer used for collecting memory usage information.
    FIntervalInfoMemory      : NativeUInt;         // The interval (in milliseconds) at which to collect memory usage information.
    FMemPrevUsage            : DWORD;              // The previous memory usage (in bytes) of the system.
    FMemApplicationPrevUsage : DWORD;              // The previous memory usage (in bytes) of the application.
    FItemNameFile            : integer;            // An index that corresponds to the current log file name.  

    /// <summary>
    /// Writes the specified log message to the log file.
    /// </summary>
    /// <param name="pInfoLog">The log message to write.</param>
    procedure THLOG__WriteLogOnFile(pInfoLog: pMsgLog);

    /// <summary>
    /// Writes the specified text to the file with the specified file name.
    /// </summary>
    /// <param name="aFileName">The name of the file to write to.</param>
    /// <param name="aText">The text to write.</param>
    procedure THLOG__WriteText(const aFileName, aText: AnsiString);

    /// <summary>
    /// Deletes the log file(s) older than TWpcapLogger.MaxDayLog.
    /// </summary>
    procedure THLOG__DeleteFileLog;

    /// <summary>
    /// Gets the data contained in the specified file.
    /// </summary>
    /// <param name="aFileName">The name of the file to get data from.</param>
    /// <returns>The data contained in the specified file.</returns>
    function THLOG__GetData(aFileName: AnsiString): AnsiString;

    /// <summary>
    /// Starts a timer with the specified interval.
    /// </summary>
    /// <param name="aTimer">The timer to start.</param>
    /// <param name="aInterval">The interval for the timer, in milliseconds.</param>
    procedure THLOG__StartTimer(var aTimer: NativeUInt; aInterval: integer);

    /// <summary>
    /// Stops the specified timer.
    /// </summary>
    /// <param name="aTimer">The timer to stop.</param>
    procedure THLOG__StopTimer(var aTimer: NativeUInt);

    /// <summary>
    /// Writes the current memory usage statistics to the log file.
    /// </summary>
    procedure THLOG__WriteiInfoMemory();

    /// <summary>
    /// Truncates the specified string to a maximum length.
    /// </summary>
    /// <param name="aText">The string to truncate.</param>
    /// <param name="MaxLen">The maximum length of the string.</param>
    procedure THLOG__StrToFillLen(var aText: AnsiString; MaxLen: integer);
        
    /// <summary>
    /// Gets the size in bytes of the specified file.
    /// </summary>
    /// <param name="aFileName">The name of the file to get the size of.</param>
    /// <returns>The size of the specified file in bytes.</returns>
    function SDK_GetFileSize(aFileName: AnsiString): integer;

    /// <summary>
    /// Converts the specified log level to a string representation.
    /// </summary>
    /// <param name="aLevel">The log level to convert.</param>
    /// <returns>The string representation of the specified log level.</returns>
    function LevelToStr(const aLevel: TWpcapLvlLog): AnsiString;
  protected

    /// <summary>
    /// Executes the thread's main loop.
    /// </summary>
    procedure Execute; override;
  public

    /// <summary>
    /// Creates a new instance of the TThreadLog class.
    /// </summary>
    /// <param name="aEventStart">The handle of the event used to start the thread.</param>
    /// <param name="aParentClass">A reference to the parent TWpcapLogger object.</param>
    constructor Create(aEventStart: Thandle; aParentClass: TWpcapLogger);

    /// <summary>
    /// Destroys the current instance of the TThreadLog class.
    /// </summary>
    Destructor Destroy; override;
  end;

  /// <summary>
  /// A class that provides logging functionality for WinPcap-related operations.
  /// </summary>
  TWpcapLogger = class(TComponent)
  private
    FPath          : AnsiString;     // The path to the log file.
    FThLog         : TThreadLog;     // The thread log used for writing to the log file.
    FOnError       : TEvError;       // The event to be called when an error occurs.
    FOnInfo        : TEvInfo;        // The event to be called when an info message is written to the log file.
    FNumDayLog     : LongInt;        // The maximum number of days for which log entries should be kept.
    FInfoMemory    : TInfoMemory;    // The object that stores information about memory usage.
    FMaxLogSize_MB : Integer;        // The maximum size (in MB) of the log file before it is rotated.
    FPrefixFile    : AnsiString;     // The prefix to be used when naming the log file.
    FActive        : Boolean;        // Whether or not logging is currently enabled.
    FDebug         : Boolean;        // Whether or not debug messages should be written to the log file. 

    /// <summary>
    ///  Sets the Prefix on filename to the given value.
    /// </summary>    
  	procedure SetPrefix(const aValue : AnsiString);

    /// <summary>
    /// Sets the MaxDayLog property to the given value.
    /// </summary>    
    procedure SetMaxDayLog(const aValue : LongInt);

    /// <summary>
    /// Sets the PathLog property to the given value.
    /// </summary>    
    procedure SetPath(const aValue: AnsiString);

    /// <summary>
    /// Fire internal error message to a dedicate event
    /// </summary>    
    procedure LOG__Error(aFunction : AnsiString; aErrorType : AnsiString);

    /// <summary>
    /// Initializes the log file and associated objects.
    /// </summary>    
    function  LOG__InitLog:boolean;

    /// <summary>
    /// Frees the resources associated with the log file.
    /// </summary>        
    procedure LOG__FreeLog;

    /// <summary>
    /// Returns the path of application
    /// </summary>        
    function SDK_GetModulePath: AnsiString;
  public

    /// <summary>
    /// Create object
    /// </summary>      
    constructor Create(AOwner: TComponent); override;

    /// <summary>
    /// Destroy object
    /// </summary>        
    destructor Destroy; override;
    
    /// <summary>
    /// Writes  message to the log file.
    /// </summary>        
    procedure LOG__WriteiLog(aFunctionName : String; aDescription : String; aLevelLog : TWpcapLvlLog);
  published
    /// <summary>
    /// The path to the log file.
    /// </summary>
    property PathLog: AnsiString read FPath write SetPath;

    /// <summary>
    /// The maximum number of days for which log entries should be kept.
    /// </summary>
    property MaxDayLog: LongInt read FNumDayLog write SetMaxDayLog default 60;

    /// <summary>
    /// The object that stores information about memory usage.
    /// </summary>
    property InfoMemory: TInfoMemory read FInfoMemory write FInfoMemory;

    /// <summary>
    /// Whether or not logging is currently enabled.
    /// </summary>
    property Active: Boolean read FActive write FActive default True;

    /// <summary>
    /// Whether or not debug messages should be written to the log file.
    /// </summary>
    property Debug: Boolean read FDebug write FDebug default false;

    /// <summary>
    /// The maximum size (in MB) of the log file before it is rotated.
    /// </summary>
    property MaxLogSize_MB: Integer read FMaxLogSize_MB write FMaxLogSize_MB;

    /// <summary>
    /// The prefix to be used when naming the log file.
    /// </summary>
    property Prefix: AnsiString read FPrefixFile write SetPrefix;

    /// <summary>
    /// Event for internal info
    /// </summary>    
    property OnInfo              : TEvInfo       read FOnInfo         write FOnInfo;

    /// <summary>
    /// Event for internal error
    /// </summary>        
    property OnError             : TEvError      read FOnError        write FOnError;
  end;

implementation

constructor TWpcapLogger.Create(AOwner: TComponent);
begin
  Try
    inherited Create(AOwner);

    FThLog := nil;

    SetPath(String.Empty);

    if not LOG__InitLog then
    begin
      LOG__Error('TRESILOG.Create','Initializing Thread Log Failed');
      FThLog      := nil;
      FInfoMemory := TInfoMemory.Create(0);
    end
    else
      FInfoMemory := TInfoMemory.Create(FThLog.ThreadID);

    FMaxLogSize_MB := 1024;{1 GB}
  Except
    LOG__Error('TRESILOG.Create','Generic');
  end;
end;

destructor  TWpcapLogger.Destroy();
begin
  Try
    FInfoMemory.Free;
    LOG__FreeLog();
    Inherited Destroy;
  Except
    LOG__Error('TRESILOG.Destroy','Generic');
  end;
end;

function TWpcapLogger.LOG__InitLog():boolean;
var LEventInit : Thandle;
begin
  Result := false;
  Try
    LEventInit := CreateEvent(nil, false, false, nil);

    FThLog     := TThreadLog.create(LEventInit,Self);
    FThlog.Start;
    if (WaitForSingleObject(LEventInit,10000) = WAIT_OBJECT_0) then
      Result := true;
    ResetEvent(LEventInit);
  Except
    LOG__Error('LOG__InitLog','Generic');
  end;
end;

procedure TWpcapLogger.LOG__FreeLog();
var LEventEnd : Thandle;
begin
  Try
    if Not Assigned(FThLog) then Exit;

    LEventEnd := CreateEvent(nil, false, false, nil);

    if PostThreadMessage(FThLog.ThreadID, MSG_TO_THLOG_KILL, LEventEnd, 0) then
        WaitForSingleObject(LEventEnd, 10000);
    ResetEvent(LEventEnd);
  Except
    LOG__Error('LOG__FreeLog','Generic');
  end;

  FreeAndNil(FThLog);
end;

procedure TWpcapLogger.LOG__WriteiLog(aFunctionName : String; aDescription : String; aLevelLog : TWpcapLvlLog);
var LpInfoLog  : pMsgLog;
    LErrorCode : integer;
begin
  if not Active then Exit;

  if not Debug then
  begin
    if aLevelLog = TWLLDebug then Exit;    
  end;
  LErrorCode := GetLastError;
  
  Try
    if (FThLog <> nil) then
    begin
      New(LpInfoLog);

      LpInfoLog^.FunctionName := AnsiString(aFunctionName);
      LpInfoLog^.Level        := aLevelLog;
      LpInfoLog^.Description  := AnsiString(aDescription);
      LpInfoLog^.ErrorCode    := LErrorCode;
      LpInfoLog^.TabCount     := 0;

      if Not PostThreadMessage(FThLog.ThreadID, MSG_TO_THLOG_LOG, 0, LongInt(LpInfoLog)) then
        Dispose(LpInfoLog)
    end
  Except
    LOG__Error('LOG__ScriviLog','Generic');
  end;
end;

procedure TWpcapLogger.LOG__Error(aFunction : AnsiString; aErrorType : AnsiString);
begin
  Try
    if Assigned(FOnError)then
      FOnError(aFunction,aErrorType);
  Except
  	//
  end;
end;

function TWpcapLogger.SDK_GetModulePath: AnsiString;
Var LTest   : AnsiString;
    LRes    : Longint;
   LCurSize : Longint;
begin
  LCurSize := 1024;
  SetLength(LTest, LCurSize);
  LRes := GetModuleFileNameA(GetModuleHandle(nil), PAnsiChar(LTest), LCurSize);
  if (LRes > LCurSize) then
  begin
    LCurSize := LRes + 10;
    SetLength(LTest, LCurSize);
    LRes := GetModuleFileNameA(GetModuleHandle(nil), PAnsiChar(LTest), LCurSize);
  end;
  Setlength(LTest, LRes);
  Result := ExtractFilePath(LTest);
end;

procedure TWpcapLogger.SetPath(const aValue: AnsiString);
begin
  Try
    if Trim(aValue) = '' then
      FPath := System.AnsiStrings.Format('%sLog\',[SDK_GetModulePath])
    else
      FPath := IncludeTrailingPathDelimiter(Trim(aValue));
  Except
    LOG__Error('TRESILOG.SetPath','Generic');
  end;
end;

procedure TWpcapLogger.SetMaxDayLog(const aValue : Integer);
begin
  Try
    FNumDayLog := aValue;
    if Assigned(FThLog) then
    begin
      if aValue > 0 then
        PostThreadMessage(FThLog.ThreadID, MSG_TO_THLOG_START_TIMER_SVE, 0, 0)
      else
        PostThreadMessage(FThLog.ThreadID, MSG_TO_THLOG_STOP_TIMER_SVE, 0, 0);
    end;
  Except
    LOG__Error('TRESILOG.SetGiorniDiLog','Generic');
  end;
end;

{Class Thread Log}
constructor TThreadLog.Create(aEventStart : Thandle; aParentClass : TWpcapLogger);
begin
  Try
    inherited Create(True);

    FEventStart              := aEventStart;
    FParentClass             := aParentClass;
    FTimerDeleteLog          := 0;
    FMemPrevUsage            := 0;
    FMemApplicationPrevUsage := 0;
    FTimerInfoMemory         := 0;
    FIntervalInfoMemory      := 0;
    FItemNameFile            := 0;
  Except
  	//Errore
  end;
end;

destructor TThreadLog.Destroy;
begin
  Try
    inherited Destroy;
  except
  end
end;

procedure TThreadLog.Execute;
var LEventEnd : Thandle;
    LMsg      : TMsg;
begin
  LEventEnd := 0;
  Try
    PeekMessage(LMsg, 0, WM_USER, WM_USER, PM_NOREMOVE);

    SetEvent(FEventStart);

    while (Terminated = False) do
    begin
      GetMessage(LMsg, 0, WM_TIMER, MSG_TO_THLOG_STOP);

      case LMsg.message of

        MSG_TO_THLOG_START_TIMER_SVE  : THLOG__StartTimer(FTimerDeleteLog,300000);

        MSG_TO_THLOG_STOP_TIMER_SVE   : THLOG__StopTimer(FTimerDeleteLog);

        MSG_TO_THLOG_START_TIMER_INFO :
          begin
            FIntervalInfoMemory := LMsg.wParam;
            THLOG__StartTimer(FTimerInfoMemory, FIntervalInfoMemory);
          end;

        MSG_TO_THLOG_STOP_TIMER_INFO  : THLOG__StopTimer(FTimerInfoMemory);

        WM_TIMER :
          begin
            if (LMsg.wParam = FTimerDeleteLog) then
            begin
              THLOG__StopTimer(FTimerDeleteLog);
              THLOG__DeleteFileLog();
              THLOG__StartTimer(FTimerDeleteLog,DELTA_TIMER_CHECK);
            end
            else
            begin
              THLOG__StopTimer(FTimerInfoMemory);
              THLOG__WriteiInfoMemory();
              THLOG__StartTimer(FTimerInfoMemory,FIntervalInfoMemory);
            end;
          end;

        MSG_TO_THLOG_LOG  : THLOG__WriteLogOnFile(pMsgLog(LMsg.lParam));

        MSG_TO_THLOG_KILL :
          begin
            LEventEnd := LMsg.wParam;
            SetEvent(LEventEnd);
            Terminate;
          end;

      end;
    end;
    
    if(LEventEnd > 0)then
      SetEvent(LEventEnd);
  Except
    if (Assigned(FParentClass.OnError)) then
      FParentClass.OnError('TThreadLog.Execute','Generic');
  end;

  CloseHandle(FEventStart);
  if LEventEnd <> 0 then  
    CloseHandle(LEventEnd);
end;

function  TThreadLog.SDK_GetFileSize(aFileName : AnsiString): integer;
var LpFile : integer;
begin
  Result := 0;
  try
    {$I-}
      LpFile  := FileOpen(string(aFileName), fmShareDenyWrite);
      Result  := GetFileSize(LpFile,nil);
      FileClose(LpFile);
    {$I+}
  except
  end;
end;

Function TThreadLog.LevelToStr(const aLevel : TWpcapLvlLog):AnsiString;
begin
  case aLevel of
    TWLLException : Result := 'Exception' ;
    TWLLError     : Result := 'Error' ;
    TWLLWarning   : Result := 'Warning' ;
    TWLLInfo      : Result := 'Info' ;
    TWLLTiming    : Result := 'Timing' ;
    TWLLDebug     : Result := 'DEBUG' ;
  end;
end;

procedure TThreadLog.THLOG__WriteLogOnFile(pInfoLog : pMsgLog);
var LGlobalText,
    LLevelText,
    LLevelName,
    aFileName :AnsiString;
    LTime     : AnsiString;

  function GetFileName(LevelName : AnsiString) : AnsiString;
  var LLogFileName : AnsiString;
      Index : Integer;
  begin
    for Index := 0 to 100 do
      begin
        LLogFileName := System.AnsiStrings.Format('%s%s_%d%s%s%s',[FParentClass.FPath,FormatDateTime(AnsiString('yyyymmdd'), now),Index,
                                                                   PREFIX_FILE_LOG,LevelName,EXTENSION]);

        if(FileExists(string(LLogFileName)))then
        begin
          if(SDK_GetFileSize(LLogFileName) < (FParentClass.MaxLogSize_MB * MB))then
            begin
              Result := LLogFileName;
              Break;
            end
          else
            Continue;
        end
        else
        begin
          Result := LLogFileName;
          Break;
        end;
      end;
  end;

begin
  Try

    {Formatto il nome del livello}
    LLevelName := System.AnsiStrings.Format('[ %s ]',[LevelToStr(pInfoLog^.Level)]);
    THLOG__StrToFillLen(LLevelName,MAX_LEN_LEVEL_NAME);

    LTime       := AnsiString(FormatDateTime(AnsiString('hh:nn:ss:zzz'),now));
    LGlobalText := System.AnsiStrings.Format('%s%s %s %s',[LTime,LLevelName,pInfoLog^.FunctionName,pInfoLog^.Description]);
    LLevelText  := System.AnsiStrings.Format('%s%s %s',[LTime,pInfoLog^.FunctionName,pInfoLog^.Description]);
    
    if (pInfoLog^.ErrorCode > 0) then
    begin
      LGlobalText := System.AnsiStrings.Format('%s[WLE:%s]',[LGlobalText,SysErrorMessage(pInfoLog^.ErrorCode)]);
      LLevelText  := System.AnsiStrings.Format('%s[WLE:%s]',[LLevelText,SysErrorMessage(pInfoLog^.ErrorCode)]);
    end;

    aFileName := System.AnsiStrings.Format('%s%s%s%s%s%s',[FParentClass.FPath,FormatDateTime('yyyymmdd',now),PREFIX_FILE_LOG,FParentClass.Prefix,GLOBAL_FILE_NAME,EXTENSION]);

    if not FileExists(string(aFileName)) then
      THLOG__WriteText(aFileName,'*************** START LOG GLOBAL LEVEL ****************');

    THLOG__WriteText(aFileName,LGlobalText);

    aFileName := System.AnsiStrings.Format('%s%s%s%s%s%s',[FParentClass.FPath,FormatDateTime('yyyymmdd',now),PREFIX_FILE_LOG,FParentClass.Prefix,LevelToStr(pInfoLog^.Level),EXTENSION]);

    if not FileExists(string(aFileName)) then
      THLOG__WriteText(aFileName,'*************** START LOG LEVEL ['+ LevelToStr(pInfoLog^.Level)+'] ****************');

    THLOG__WriteText(aFileName,LLevelText);

    Dispose(pInfoLog);    
  Except
    if (Assigned(FParentClass.OnError)) then
      FParentClass.OnError('TThreadLog.THLOG__ScriviLogSuFile','Generic');
  end;
end;

procedure TThreadLog.THLOG__WriteiInfoMemory();
var LFileName                   : AnsiString;
    LText                       : AnsiString;
    LTmp                        : TMEMORYSTATUS;
    LMemtUsageActive            : DWORD;
    LMemApplicationUsageActive  : DWORD;
    BaseName                    : Array[0..249] of AnsiChar;
    BaseNameStr                 : AnsiString;
    hProcess                    : THandle;
    Counters                    : PROCESS_MEMORY_COUNTERS;

    function GetStatusMemory(MemAtt,MemPrec : DWord):AnsiString;
     begin
       if (MemAtt = MemPrec) then
         Result := 'STABLE'
       else if (MemAtt > MemPrec) then
         Result := 'INCREASE'
       else
        Result := 'DECREASE';
     end;

begin
  Try
    LMemApplicationUsageActive := 20;
    LFileName                  := System.AnsiStrings.Format('%s%s%s%s%s%s',[FParentClass.FPath,FormatDateTime('yyyymmdd',now),PREFIX_FILE_LOG,FParentClass.Prefix,GLOBAL_FILE_NAME,EXTENSION]);
    LText                      := System.AnsiStrings.Format( '%s -> ',[FormatDateTime('HH:NN:SS:ZZZ', now)]);

    if (FileExists(string(LFileName)) = false) then
      THLOG__WriteText(LFileName,' *************** Start Log Global Level ****************');

    hProcess := GetCurrentProcess();
    if (GetProcessMemoryInfo(hProcess, @Counters, Sizeof(Counters)) = True) then
      LMemApplicationUsageActive := Counters.WorkingSetSize;

    GetModuleBaseNameA(hProcess, 0, BaseName, Sizeof(BaseName));
    BaseNameStr := System.AnsiStrings.StrPas(BaseName);

    CloseHandle(hProcess);

    FillChar(LTmp,Sizeof(LTmp),0);
    LTmp.dwLength := SizeOf(TMEMORYSTATUS);
    GlobalMemoryStatus(LTmp);
    LMemtUsageActive   := LTmp.dwTotalVirtual - LTmp.dwAvailVirtual;

    THLOG__WriteText(LFileName,LText);
    THLOG__WriteText(LFileName,LText + '***********************************************************************');
    THLOG__WriteText(LFileName,LText + '*                        I N F O   M E M O R Y                        *');
    THLOG__WriteText(LFileName,LText + '***********************************************************************');
    THLOG__WriteText(LFileName,LText + '          |Physical Memory System   - Total      (RAM KB)  : ' + System.AnsiStrings.Format('%d',[(Round(LTmp.dwTotalPhys/1024))]));
    THLOG__WriteText(LFileName,LText + '          |Physical Memory System   - Available  (RAM KB)  : ' + System.AnsiStrings.Format('%d',[(Round(LTmp.dwAvailPhys/1024))]));
    THLOG__WriteText(LFileName,LText + ' SISTEMA  |Private Memory System    - Total      (DISK KB) : ' + System.AnsiStrings.Format('%d',[(Round(LTmp.dwTotalPageFile/1024))]));
    THLOG__WriteText(LFileName,LText + '          |Private Memory System    - Available  (DISK KB) : ' + System.AnsiStrings.Format('%d',[(Round(LTmp.dwAvailPageFile/1024))]));
    THLOG__WriteText(LFileName,LText + '          |Private Memory Process   - Total      (DISK KB) : ' + System.AnsiStrings.Format('%d',[(Round(LTmp.dwTotalVirtual/1024))]));
    THLOG__WriteText(LFileName,LText);
    THLOG__WriteText(LFileName,LText + '          |Virtual Memory used Current  in KByte           : ' + System.AnsiStrings.Format('%d',[(Round(LMemtUsageActive/1024))]));
    THLOG__WriteText(LFileName,LText + ' PROC.(VR)|Virtual Memory used Previous in KByte           : ' + System.AnsiStrings.Format('%d',[(Round(FMemPrevUsage/1024))]));
    THLOG__WriteText(LFileName,LText + '          |State                                           : ' + GetStatusMemory(LMemtUsageActive,FMemPrevUsage));
    THLOG__WriteText(LFileName,LText);
    THLOG__WriteText(LFileName,LText + '          |Process Name                                    : ' + BaseNameStr);
    THLOG__WriteText(LFileName,LText + '          |Virtual Memory used Current   in KByte          : ' + System.AnsiStrings.Format('%d',[(Round(LMemApplicationUsageActive/1024))]));
    THLOG__WriteText(LFileName,LText + ' PROC.(FS)|Virtual Memory used Previous  in KByte          : ' + System.AnsiStrings.Format('%d',[(Round(FMemApplicationPrevUsage/1024))]));
    THLOG__WriteText(LFileName,LText + '          |State                                           : ' + GetStatusMemory(LMemApplicationUsageActive,FMemApplicationPrevUsage));
    THLOG__WriteText(LFileName,LText + '***********************************************************************');
    THLOG__WriteText(LFileName,LText);

    FMemPrevUsage := LMemtUsageActive;
    FMemApplicationPrevUsage := LMemApplicationUsageActive;
  Except
    if (Assigned(FParentClass.OnError)) then
      FParentClass.OnError('TThreadLog.THLOG__ScriviLogSuFile','Generic');
  end;
end;

procedure TThreadLog.THLOG__WriteText(const aFilename, aText: AnsiString);
CONST ERROR_FILE_OPEN =  -1;
var LpFile				: integer;
begin
  Try
    if not System.IOUtils.TDirectory.Exists(String(FParentClass.FPath)) then
      System.IOUtils.TDirectory.CreateDirectory(String(FParentClass.FPath));

    if(System.IOUtils.TFile.Exists(string(aFilename)) = true) then
      begin
        LpFile := FileOpen(string(aFilename), fmOpenReadWrite);

        if LpFile <> ERROR_FILE_OPEN then
	        FileSeek(LpFile,0,2);
      end
    else
      begin
        {Se non esiste bisogna crearlo la routine FILEOPEN non lo crea altrimenti!!}
        LpFile := FileCreate(string(aFilename));

        if LpFile <> ERROR_FILE_OPEN then
	        FileSeek(LpFile,0,2);
      end;

    if (LpFile <> ERROR_FILE_OPEN) then
      begin
        FileWrite(LpFile, (aText+AnsiString(#13#10))[1],Length(aText)+2);
        FileClose(LpFile);
      end;
  Except
    if (Assigned(FParentClass.OnError)) then
      FParentClass.OnError('TThreadLog.ScriviTesto','Generic');
  end;
end;

function GetFileList(const aPath: AnsiString; aExtFile : AnsiString; var aFileList: TStringList): Integer;
var
  Status: Integer;
  SearchRec: TSearchRec;
begin
  Result := 0;
  {$WARN SYMBOL_PLATFORM OFF}
  Status := FindFirst(string(IncludeTrailingPathDelimiter(aPath)+aExtFile), faReadOnly or faArchive, SearchRec);
  {$WARN SYMBOL_PLATFORM ON}
  try
    while Status = 0 do
    begin
      if (SearchRec.Name <> '.') and (SearchRec.Name <> '..') then
        begin
         aFileList.Add(SearchRec.Name);
         Inc(Result);
        end;

      Status := FindNext(SearchRec);
    end;
  finally
    FindClose(SearchRec);
  end;

  if (aFileList.Count > 0) then
    aFileList.Sort();
end;

procedure TThreadLog.THLOG__DeleteFileLog();
var LFileDate          : AnsiString;
    LDeleteDay        : AnsiString;
    I                 : Integer;
    LFileLogList      : TStringList;
begin
  Try
    LFileLogList := TStringList.Create;
    Try
      LDeleteDay := AnsiString(FormatDateTime('yyyymmdd',now - FParentClass.MaxDayLog));

      GetFileList(FParentClass.FPath, '*' + EXTENSION, LFileLogList);

      for I := 0 to LFileLogList.Count - 1 do
      begin
        LFileDate := THLOG__GetData(AnsiString(LFileLogList[I]));

        if (LFileDate < LDeleteDay) then
          DeleteFile(string(FParentClass.FPath) + LFileLogList[I]);
      end;
    Finally
      LFileLogList.Free;
    End;
  Except
    if (Assigned(FParentClass.OnError)) then
      FParentClass.OnError('THLOG__DeleteFileLog','Generic');
  end;
end;

function TThreadLog.THLOG__GetData(aFileName:AnsiString):AnsiString;
begin
  Try
    Result := copy(aFileName, 1, 8);
  Except
    if (Assigned(FParentClass.OnError)) then
      FParentClass.OnError('THLOG__RicavaData','Generic');
  end;
end;
procedure TThreadLog.THLOG__StartTimer(var aTimer : NativeUInt; aInterval : integer);
begin
  Try
    if (aTimer > 0) then
      THLOG__StopTimer(aTimer);

    aTimer := setTimer(0,1,aInterval,nil);
  Except
  End
end;

procedure TThreadLog.THLOG__StopTimer(var aTimer : NativeUInt);
begin
  Try
   if (aTimer > 0) then
     begin
       if (KillTimer(0,aTimer) = true) then
         aTimer := 0;
     end
  Except
  End
end;


constructor TInfoMemory.Create(ThLogId: Integer);
begin
  Try
    Inherited Create();
    FThLogId := ThLogId;
  Except
  End;
end;

procedure TInfoMemory.SetEnableInfoMemory(aValue : boolean);
begin
  Try
    FEnableInfoMemory := aValue;
    if (FThLogId > 0) then
    begin
      if (FEnableInfoMemory = true) and (FInterval > 0) then
        PostThreadMessage(FThLogId, MSG_TO_THLOG_START_TIMER_INFO, FInterval * TIME_MINUTE,0)
      else
        PostThreadMessage(FThLogId, MSG_TO_THLOG_STOP_TIMER_INFO, 0,0);
    end;
  except
  end
end;

procedure TInfoMemory.SetInfoMemoryInterval(aValue : integer);
begin
  Try
    FInterval := aValue;

    if (FThLogId > 0) then
    begin
      if (FEnableInfoMemory = true) and (FInterval > 0) then
        PostThreadMessage(FThLogId, MSG_TO_THLOG_START_TIMER_INFO, FInterval * TIME_MINUTE,0)
      else
        PostThreadMessage(FThLogId, MSG_TO_THLOG_STOP_TIMER_INFO, 0,0);
    end;
  Except
  End
end;

procedure TThreadLog.THLOG__StrToFillLen(var aText : AnsiString; MaxLen : integer);
var LLenStr : Integer;
    LDiff   : integer;
    LInd    : Integer;
begin
	Try
    LLenStr := Length((aText));

    if (LLenStr <> MaxLen) then
      begin
        if (LLenStr < MaxLen) then
        begin
          LDiff := MaxLen - LLenStr;

          for LInd := 1 to LDiff do
            aText := aText + ' ';
        end
        else
          aText := Copy(aText, 1, MaxLen);
      end;
	Except
  	//Errore
  end;
end;

procedure TWpcapLogger.SetPrefix(const aValue: AnsiString);
begin
  FPrefixFile := aValue;

  if(FPrefixFile <> '')then
    FPrefixFile := FPrefixFile + '_';
end;


end.

