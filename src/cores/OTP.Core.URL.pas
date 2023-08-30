unit OTP.Core.URL;

interface

{$SCOPEDENUMS ON}

uses
  System.SysUtils;

type
  TAuthType = (TOTP, HOTP);

  TOTPAuthURL = record
  private
    FAuthType: TAuthType;
    FIssuer: string;
    FLabelInfo: string;
    FImage: string;
    FSecret: string;
    FPeriod: Integer;
    FAlgorithm: string;
    FDigits: Integer;
    FCounter: Integer;
    procedure DecomposeURI(const AURIStr: string; ARaiseNoSchema: Boolean);
  public
    /// <summary>
    /// Initializes a TOTPAuthURL from a string
    /// </summary>
    constructor Create(const AURIStr: string);
    property AuthType: TAuthType read FAuthType write FAuthType;
    property Issuer: string read FIssuer write FIssuer;
    property LabelInfo: string read FLabelInfo write FLabelInfo;
    property Secret: string read FSecret write FSecret;
    property Image: string read FImage write FImage;
    property Algorithm: string read FAlgorithm write FAlgorithm;
    property Period: Integer read FPeriod write FPeriod;
    property Digits: Integer read FDigits write FDigits;
    property Counter: Integer read FCounter write FCounter;

    function ToString: string; inline;
  end;

implementation

uses
  System.Net.URLClient, System.NetEncoding, OTP.Consts;

{ TOTPAuthURL }

constructor TOTPAuthURL.Create(const AURIStr: string);
begin
  DecomposeURI(AURIStr, True);
end;

procedure TOTPAuthURL.DecomposeURI(const AURIStr: string; ARaiseNoSchema: Boolean);
begin
  var URI := TURI.Create(TNetEncoding.URL.Decode(AURIStr));

  //auth type
  if URI.Host.ToLower = 'totp' then
    FAuthType := TAuthType.TOTP
  else if URI.Host.ToLower = 'hotp' then
    FAuthType := TAuthType.HOTP
  else
    FAuthType := TAuthType.TOTP;

  //label, issuer
  var Path := URI.Path.Trim(['/']).Split([':']);
  if Length(Path) > 1 then
  begin
    FIssuer := Path[0];
    FLabelInfo := Path[1];
  end
  else
  begin
    FIssuer := '';
    FLabelInfo := Path[0];
  end;

  //params
  FSecret := '';
  FImage := '';
  FAlgorithm := '';
  FPeriod := KEY_REGENERATION;
  FDigits := OTP_LENGTH;
  FCounter := 0;
  for var Param in URI.Params do
  begin
    if Param.Name = 'secret' then
      FSecret := Param.Value
    else if Param.Name = 'image' then
      FImage := Param.Value
    else if Param.Name = 'issuer' then
      FIssuer := Param.Value
    else if Param.Name = 'counter' then
      FCounter := StrToIntDef(Param.Value, 0)
    else if Param.Name = 'period' then
      FPeriod := StrToIntDef(Param.Value, KEY_REGENERATION)
    else if Param.Name = 'digits' then
      FDigits := StrToIntDef(Param.Value, OTP_LENGTH)
    else if Param.Name = 'algorithm' then
      FAlgorithm := Param.Value;
  end;
end;

function TOTPAuthURL.ToString: string;
begin
  if FLabelInfo.IsEmpty then
    raise Exception.Create('Label must be defined');
  var URI: TURI;
  //scheme
  URI.Scheme := OTP_SCHEME;
  //auth
  case FAuthType of
    TAuthType.TOTP:
      URI.Host := 'totp';
    TAuthType.HOTP:
      URI.Host := 'hotp';
  end;
  //path
  if FIssuer.IsEmpty then
    URI.Path := '/' + FLabelInfo
  else
    URI.Path := '/' + FIssuer + ':' + FLabelInfo;
  //params
  if not FSecret.IsEmpty then
    URI.AddParameter('secret', FSecret);
  if not FImage.IsEmpty then
    URI.AddParameter('image', FImage);
  if not FIssuer.IsEmpty then
    URI.AddParameter('issuer', FIssuer);
  URI.AddParameter('period', FPeriod.ToString);
  URI.AddParameter('digits', FDigits.ToString);
  if FAuthType = TAuthType.HOTP then
    URI.AddParameter('counter', FCounter.ToString);
  if not FAlgorithm.IsEmpty then
    URI.AddParameter('algorithm', FAlgorithm);

  Result := URI.ToString;
end;

end.

