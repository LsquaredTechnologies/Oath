using System;
using System.Text;
using Xunit;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    public class TotpGeneratorTests
    {
        [Theory]
        [InlineData("1970-01-01T00:00:59Z", "94287082")]
        [InlineData("2005-03-18T01:58:29Z", "07081804")]
        [InlineData("2005-03-18T01:58:31Z", "14050471")]
        [InlineData("2009-02-13T23:31:30Z", "89005924")]
        [InlineData("2033-05-18T03:33:20Z", "69279037")]
        [InlineData("2603-10-11T11:33:20Z", "65353130")]
        public void Generate_WithSha1Returns8Digits(string dateStr, string expectedCode)
        {
            // arrange
            var date = DateTimeOffset.Parse(dateStr);
            var options = new TotpGeneratorOptions { CodeLength = 8, AlgorithmName = "HMACSHA1", TimeProvider = new ConstantTimeProvider(date) };
            var hotpGenerator = new TotpGenerator(options);

            // act
            var actualCode = hotpGenerator.Generate(Secret20);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        [Theory]
        [InlineData("1970-01-01T00:00:59Z", "46119246")]
        [InlineData("2005-03-18T01:58:29Z", "68084774")]
        [InlineData("2005-03-18T01:58:31Z", "67062674")]
        [InlineData("2009-02-13T23:31:30Z", "91819424")]
        [InlineData("2033-05-18T03:33:20Z", "90698825")]
        [InlineData("2603-10-11T11:33:20Z", "77737706")]
        public void Generate_WithSha256Returns8Digits(string dateStr, string expectedCode)
        {
            // arrange
            var date = DateTimeOffset.Parse(dateStr);
            var options = new TotpGeneratorOptions { CodeLength = 8, AlgorithmName = "HMACSHA256", TimeProvider = new ConstantTimeProvider(date) };
            var hotpGenerator = new TotpGenerator(options);

            // act
            var actualCode = hotpGenerator.Generate(Secret32);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        [Theory]
        [InlineData("1970-01-01T00:00:59Z", "90693936")]
        [InlineData("2005-03-18T01:58:29Z", "25091201")]
        [InlineData("2005-03-18T01:58:31Z", "99943326")]
        [InlineData("2009-02-13T23:31:30Z", "93441116")]
        [InlineData("2033-05-18T03:33:20Z", "38618901")]
        [InlineData("2603-10-11T11:33:20Z", "47863826")]
        public void Generate_WithSha512Returns8Digits(string dateStr, string expectedCode)
        {
            // arrange
            var date = DateTimeOffset.Parse(dateStr);
            var options = new TotpGeneratorOptions { CodeLength = 8, AlgorithmName = "HMACSHA512", TimeProvider = new ConstantTimeProvider(date) };
            var hotpGenerator = new TotpGenerator(options);

            // act
            var actualCode = hotpGenerator.Generate(Secret64);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        private static readonly byte[] Secret20 = Encoding.UTF8.GetBytes("12345678901234567890");
        private static readonly byte[] Secret32 = Encoding.UTF8.GetBytes("12345678901234567890123456789012");
        private static readonly byte[] Secret64 = Encoding.UTF8.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");
    }
}
