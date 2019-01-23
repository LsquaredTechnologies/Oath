using System;
using System.Text;
using Xunit;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    public class HotpGeneratorTests
    {
        [Theory]
        [InlineData(0, "755224")]
        [InlineData(1, "287082")]
        [InlineData(2, "359152")]
        [InlineData(3, "969429")]
        [InlineData(4, "338314")]
        [InlineData(5, "254676")]
        [InlineData(6, "287922")]
        [InlineData(7, "162583")]
        [InlineData(8, "399871")]
        [InlineData(9, "520489")]
        public void Generate_WithSha1IncrementedCounter_Returns6Digits(int counter, string expectedCode)
        {
            // arrange
            var options = new OtpGeneratorOptions { CodeLength = 6 };
            var hotpGenerator = new HotpGenerator(options);

            // act
            var actualCode = hotpGenerator.Generate(Secret, counter);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        private static readonly byte[] Secret = Encoding.UTF8.GetBytes("12345678901234567890");
    }
}
