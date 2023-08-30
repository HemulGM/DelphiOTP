# Time-based one-time password

A Delphi library for generating one-time passwords according to RFC 4226 (HOTP Algorithm) and RFC 6238 (TOTP Algorithm).

## ⚡️ Generate a new secret
```delphi
uses
  OTP;

var
  LSecret: string;
begin
  LSecret := TOTPSecretGenerator.New
    .SetKeyLength(10)
    .Generate;
end.
```

## ⚡️ Generate a new token
```delphi
uses
  OTP;

var
  LToken: UInt32;
begin
  LToken := TOTPCalculator.New
    .SetSecret('MYSECRETBASE32')
    .SetAlgorithm(TAlgorithm.SHA1) //sha1, sha2*, md5
    .Calculate;
end.
```

## ⚡️ Validate a token
```delphi
uses
  OTP;

begin
  TOTPValidator.New(
    TOTPCalculator
      .New
      .SetSecret('MYSECRETBASE32')
  )
  .SetToken(102030)
  .Validate;
end.
```


<hr>
<p align="center">
<img src="https://dtffvb2501i0o.cloudfront.net/images/logos/delphi-logo-128.webp" alt="Delphi">
</p>
<h5 align="center">
Made with :heart: on Delphi
</h5>