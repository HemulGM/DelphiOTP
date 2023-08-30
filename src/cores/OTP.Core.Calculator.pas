unit OTP.Core.Calculator;

interface

uses
  OTP.Contract.Core.Calculator, OTP.Types;

type
  TOTPCalculator = class(TInterfacedObject, IOTPCalculator)
  private
    FSecret: string;
    FCounter: Int64;
    FKeyRegeneration: Integer;
    FLength: Byte;
    FAlgorithm: TAlgorithm;
  protected
    constructor Create;
  public
    function SetKeyRegeneration(const AKeyRegeneration: Integer): IOTPCalculator;
    function SetSecret(const ASecret: string): IOTPCalculator;
    function SetCounter(const ACounter: Int64): IOTPCalculator;
    function SetLength(const ALength: Byte): IOTPCalculator;
    function SetAlgorithm(const AAlgorithm: TAlgorithm): IOTPCalculator;
    function Calculate: UInt32;
    class function New: IOTPCalculator;
  end;

implementation

uses
  System.DateUtils, System.SysUtils, System.Hash, System.Math, OTP.Consts,
  OTP.Helper.ArrayBytes, OTP.Helper.Base32, OPT.Exception.InvalidToken,
  OTP.Resource.Exception;

{ TOTPCalculator }

function TOTPCalculator.Calculate: UInt32;
var
  LHash: TArray<Byte>;
  LTimeKey: TArray<Byte>;
  LBinSecret: TArray<Byte>;
  LOffset: UInt8;
  LBinCode: UInt32;
  LTime: Int64;
begin
  if FCounter <> -1 then
    LTime := FCounter
  else
    LTime := DateTimeToUnix(Now, False) div FKeyRegeneration;
  try
    LBinSecret := TBase32.Decode(TEncoding.UTF8.GetBytes(FSecret));
  except
    raise EOTPWrongBase32.Create(sOTPWrongBase32);
  end;

  LTimeKey := LTimeKey.FromInt64(Int64(LTime)).Reverse;

  case FAlgorithm of
    TAlgorithm.SHA1:
      LHash := THashSHA1.GetHMACAsBytes(LTimeKey, LBinSecret);
    TAlgorithm.SHA224:
      LHash := THashSHA2.GetHMACAsBytes(LTimeKey, LBinSecret, THashSHA2.TSHA2Version.SHA224);
    TAlgorithm.SHA256:
      LHash := THashSHA2.GetHMACAsBytes(LTimeKey, LBinSecret, THashSHA2.TSHA2Version.SHA256);
    TAlgorithm.SHA384:
      LHash := THashSHA2.GetHMACAsBytes(LTimeKey, LBinSecret, THashSHA2.TSHA2Version.SHA384);
    TAlgorithm.SHA512:
      LHash := THashSHA2.GetHMACAsBytes(LTimeKey, LBinSecret, THashSHA2.TSHA2Version.SHA512);
    TAlgorithm.SHA512_224:
      LHash := THashSHA2.GetHMACAsBytes(LTimeKey, LBinSecret, THashSHA2.TSHA2Version.SHA512_224);
    TAlgorithm.SHA512_256:
      LHash := THashSHA2.GetHMACAsBytes(LTimeKey, LBinSecret, THashSHA2.TSHA2Version.SHA512_256);
    TAlgorithm.MD5:
      LHash := THashMD5.GetHMACAsBytes(LTimeKey, LBinSecret);
  end;

  LOffset := LHash[High(LHash)] and $0F;

  // fix for md5
  if LOffset + 3 > High(LHash) then
    LHash := LHash + [0, 0, 0, 0, 0, 0, 0];

  LBinCode :=
    ((LHash[LOffset] and $7F) shl 24) or
    ((LHash[LOffset + 1] and $FF) shl 16) or
    ((LHash[LOffset + 2] and $FF) shl 8) or
    ((LHash[LOffset + 3] and $FF));

  Result := LBinCode mod Trunc(IntPower(10, FLength));
end;

constructor TOTPCalculator.Create;
begin
  FCounter := -1;
  FKeyRegeneration := KEY_REGENERATION;
  FLength := OTP_LENGTH;
  FAlgorithm := TAlgorithm.SHA1;
end;

class function TOTPCalculator.New: IOTPCalculator;
begin
  Result := TOTPCalculator.Create;
end;

function TOTPCalculator.SetAlgorithm(const AAlgorithm: TAlgorithm): IOTPCalculator;
begin
  Result := Self;
  FAlgorithm := AAlgorithm;
end;

function TOTPCalculator.SetCounter(const ACounter: Int64): IOTPCalculator;
begin
  Result := Self;
  FCounter := ACounter;
end;

function TOTPCalculator.SetKeyRegeneration(const AKeyRegeneration: Integer): IOTPCalculator;
begin
  Result := Self;
  FKeyRegeneration := AKeyRegeneration;
end;

function TOTPCalculator.SetLength(const ALength: Byte): IOTPCalculator;
begin
  Result := Self;
  FLength := ALength;
end;

function TOTPCalculator.SetSecret(const ASecret: string): IOTPCalculator;
begin
  Result := Self;
  FSecret := ASecret;
end;

end.

