unit OPT.Exception.InvalidToken;

interface

uses
  System.SysUtils;

type
  EOTPException = class(Exception);

  EOTPInvalidToken = class(EOTPException);

  EOTPWrongBase32 = class(EOTPException);

implementation

end.

