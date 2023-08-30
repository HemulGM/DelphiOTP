unit OTP.Helper.Base32;

interface

uses
  System.SysUtils;

type
  TBase32 = class
  public
    class function Encode(const AValue: TArray<Byte>): TArray<Byte>; overload;
    class function Decode(const AValue: TArray<Byte>): TArray<Byte>; overload;
    class function Encode(const AValue: string; const AEncoding: TEncoding): string; overload;
    class function Decode(const AValue: string; const AEncoding: TEncoding): string; overload;
  end;

const
  EncodeTable: array[0..31] of Byte = (
    Ord('A'), Ord('B'), Ord('C'), Ord('D'), Ord('E'), Ord('F'), Ord('G'),
    Ord('H'), Ord('I'), Ord('J'), Ord('K'), Ord('L'), Ord('M'), Ord('N'),
    Ord('O'), Ord('P'), Ord('Q'), Ord('R'), Ord('S'), Ord('T'), Ord('U'),
    Ord('V'), Ord('W'), Ord('X'), Ord('Y'), Ord('Z'), Ord('2'), Ord('3'),
    Ord('4'), Ord('5'), Ord('6'), Ord('7'));
  DecodeTable: array[0..90] of Int8 = (
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25);
  PadStr = Ord('=');

implementation

{ TBase32 }

class function TBase32.Decode(const AValue: TArray<Byte>): TArray<Byte>;
var
  LEncoded: TArray<Byte>;
  LBitLen: Integer;
  LLength: Integer;
  LCounter: Integer;
  LBuffer: Integer;
  LShift: Integer;
begin
  if Length(AValue) = 0 then
    Exit;
  LEncoded := AValue;
  if LEncoded[High(LEncoded)] <> PadStr then
    LEncoded := LEncoded + [PadStr];
  Result := [];
  LLength := High(LEncoded);
  LBitLen := 5;
  LBuffer := DecodeTable[LEncoded[0]];
  LCounter := 0;
  while LCounter < LLength do
  begin
    if LBitLen < 8 then
    begin
      LBuffer := LBuffer shl 5;
      Inc(LBitLen, 5);
      Inc(LCounter);
      if LEncoded[LCounter] = PadStr then
        LCounter := LLength;
      LBuffer := LBuffer + DecodeTable[LEncoded[LCounter]];
    end
    else
    begin
      LShift := LBitLen - 8;
      Result := Result + [LBuffer shr LShift];
      LBuffer := LBuffer and ((1 shl LShift) - 1);
      Dec(LBitLen, 8);
    end;
  end;
end;

class function TBase32.Encode(const AValue: TArray<Byte>): TArray<Byte>;
var
  LUnencoded: TArray<Byte>;
  LBitLen: Integer;
  LLength: Integer;
  LCounter: Integer;
  LBuffer: Integer;
  LShift: Integer;
begin
  if Length(AValue) = 0 then
    Exit;
  Result := [];
  LLength := Length(AValue) - 1;
  LBitLen := 0;
  LBuffer := 0;
  LCounter := -1;
  LUnencoded := AValue + [$0, $0, $0, $0];
  while (LCounter < LLength) or (LBitLen <> 0) do
  begin
    if LBitLen < 5 then
    begin
      LBuffer := LBuffer shl 8;
      Inc(LBitLen, 8);
      Inc(LCounter);
      LBuffer := LBuffer + Ord(LUnencoded[LCounter]);
    end;
    LShift := LBitLen - 5;
    if (LCounter - Integer(LBitLen > 8) > LLength) and (LBuffer = 0) then
      Result := Result + [PadStr]
    else
      Result := Result + [EncodeTable[LBuffer shr LShift]];
    LBuffer := LBuffer and ((1 shl LShift) - 1);
    Dec(LBitLen, 5);
  end;
end;

class function TBase32.Decode(const AValue: string; const AEncoding: TEncoding): string;
begin
  Result := AEncoding.GetString(Decode(AEncoding.GetBytes(AValue.ToUpper)));
end;

class function TBase32.Encode(const AValue: string; const AEncoding: TEncoding): string;
begin
  Result := AEncoding.GetString(Encode(AEncoding.GetBytes(AValue)));
end;

end.

