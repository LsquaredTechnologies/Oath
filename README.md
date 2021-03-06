# Oath / OpenAuTHentication

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Azure build status](https://lsquared.visualstudio.com/Oath/_apis/build/status/Oath-CI)](https://lsquared.visualstudio.com/Oath/_build/latest?definitionId=5)
[![Travis build status](https://travis-ci.org/LsquaredTechnologies/Oath.svg?branch=master)](https://travis-ci.org/LsquaredTechnologies/Oath/)
[![Coverage Status](https://coveralls.io/repos/github/LsquaredTechnologies/Oath/badge.svg?branch=master)](https://coveralls.io/github/LsquaredTechnologies/Oath?branch=master)
[![NuGet version](https://buildstats.info/nuget/Lsquared.Extensions.OpenAuth)](https://www.nuget.org/packages/Lsquared.Extensions.OpenAuth)

## Documentation

### HOTP

[RFC-4226](https://tools.ietf.org/html/rfc4226)

```csharp
var options = new OtpGeneratorOptions
{
    AlgorithmName = "HMACSHA1",  // default value
    CodeLength = 6
};
var hotpGenerator = new HotpGenerator(options);
var code = hotpGenerator.Generate(Secret, counter);
```

### TOTP

[RFC-6238](https://tools.ietf.org/html/rfc6238)

```csharp
var options = new TotpGeneratorOptions
{
    AlgorithmName = "HMACSHA256",
    CodeLength = 8,  // default value
    TimeStep = TimeSpan.FromSeconds(30), // default value
    // can also specify a time provider
    // TimeProvider = new DefaultTimeProvider()
};
var totpGenerator = new TotpGenerator(options);
var code = hotpGenerator.Generate(Secret);
```

### Oath Challenge-Response (OCRA)

[RFC-6287](https://tools.ietf.org/html/rfc6287)

```csharp
var question = int.Parse("75423695").ToString("X");
var ocraGenerator = OcraGenerator.Create("OCRA-1:HOTP-SHA1-6:QN08");
var code = ocraGenerator.Generate(Secret, question);
```

```csharp
var counter = "123";
var question = int.Parse("75423695").ToString("X");
var password = Hash("1234");
var ocraGenerator = OcraGenerator.Create("OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1");
var code = ocraGenerator.Generate(Secret, counter, question, password);
```

