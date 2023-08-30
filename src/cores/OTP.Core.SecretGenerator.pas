unit OTP.Core.SecretGenerator;

interface

uses
  OTP.Contract.Core.SecretGenerator;

type
  TOTPSecretGenerator = class(TInterfacedObject, IOTPSecretGenerator)
  private
    FKeyLength: Word;
  protected
    constructor Create;
  public
    function SetKeyLength(AKeyLength: Word): IOTPSecretGenerator;
    function Generate: string;
    class function New: IOTPSecretGenerator;
  end;

implementation

{ TOTPSecretGenerator }

uses
  System.SysUtils, System.Hash, OTP.Consts, OTP.Helper.Base32;

function TOTPSecretGenerator.Generate: string;
begin
  Result := TBase32.Encode(THash.GetRandomString(FKeyLength), TEncoding.UTF8);
end;

constructor TOTPSecretGenerator.Create;
begin
  FKeyLength := SECRET_LENGTH;
end;

class function TOTPSecretGenerator.New: IOTPSecretGenerator;
begin
  Result := TOTPSecretGenerator.Create;
end;

function TOTPSecretGenerator.SetKeyLength(AKeyLength: Word): IOTPSecretGenerator;
begin
  Result := Self;
  FKeyLength := AKeyLength;
end;

end.

