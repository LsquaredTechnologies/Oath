using System.Text;
using Xunit;

namespace Lsquared.Extensions.OpenAuth.OCRA
{
    public class OcraGeneratorTests
    {
        // OCRA-1:HOTP-SHA1-6:QN08
        [Theory]
        [InlineData(SEED20, "00000000", "237653")]
        [InlineData(SEED20, "11111111", "243178")]
        [InlineData(SEED20, "22222222", "653583")]
        [InlineData(SEED20, "33333333", "740991")]
        [InlineData(SEED20, "44444444", "608993")]
        [InlineData(SEED20, "55555555", "388898")]
        [InlineData(SEED20, "66666666", "816933")]
        [InlineData(SEED20, "77777777", "224598")]
        [InlineData(SEED20, "88888888", "750600")]
        [InlineData(SEED20, "99999999", "294470")]
        public void Generate_OneWay_WithHmacSha1TruncatedTo6DigitsUsing8DigitsQuestion(string key, string question, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA1-6:QN08");
            var questionHex = int.Parse(question).ToString("X");

            // act
            var actualCode = ocra.Generate(key, questionHex);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1
        [Theory]
        [InlineData(SEED32, "0", "12345678", PASS1234, "65347737")]
        [InlineData(SEED32, "1", "12345678", PASS1234, "86775851")]
        [InlineData(SEED32, "2", "12345678", PASS1234, "78192410")]
        [InlineData(SEED32, "3", "12345678", PASS1234, "71565254")]
        [InlineData(SEED32, "4", "12345678", PASS1234, "10104329")]
        [InlineData(SEED32, "5", "12345678", PASS1234, "65983500")]
        [InlineData(SEED32, "6", "12345678", PASS1234, "70069104")]
        [InlineData(SEED32, "7", "12345678", PASS1234, "91771096")]
        [InlineData(SEED32, "8", "12345678", PASS1234, "75011558")]
        [InlineData(SEED32, "9", "12345678", PASS1234, "08522129")]
        public void Generate_OneWay_WithHmacSha256TruncatedTo8DigitsUsing8DigitsQuestionAndSha1Password(string key, string counter, string question, string password, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1");
            var questionHex = int.Parse(question).ToString("X");

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA256-8:QN08-PSHA1
        [Theory]
        [InlineData(SEED32, "0", "00000000", PASS1234, "", "", "83238735")]
        [InlineData(SEED32, "1", "11111111", PASS1234, "", "", "01501458")]
        [InlineData(SEED32, "2", "22222222", PASS1234, "", "", "17957585")]
        [InlineData(SEED32, "3", "33333333", PASS1234, "", "", "86776967")]
        [InlineData(SEED32, "4", "44444444", PASS1234, "", "", "86807031")]
        public void Generate_OneWay_WithHmacSha256TruncatedTo8DigitsUsingSha1Password(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA256-8:QN08-PSHA1");
            var questionHex = int.Parse(question).ToString("X");

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA512-8:C-QN08
        [Theory]
        [InlineData(SEED64, "00000", "00000000", PASS1234, "", "", "07016083")]
        [InlineData(SEED64, "00001", "11111111", PASS1234, "", "", "63947962")]
        [InlineData(SEED64, "00002", "22222222", PASS1234, "", "", "70123924")]
        [InlineData(SEED64, "00003", "33333333", PASS1234, "", "", "25341727")]
        [InlineData(SEED64, "00004", "44444444", PASS1234, "", "", "33203315")]
        [InlineData(SEED64, "00005", "55555555", PASS1234, "", "", "34205738")]
        [InlineData(SEED64, "00006", "66666666", PASS1234, "", "", "44343969")]
        [InlineData(SEED64, "00007", "77777777", PASS1234, "", "", "51946085")]
        [InlineData(SEED64, "00008", "88888888", PASS1234, "", "", "20403879")]
        [InlineData(SEED64, "00009", "99999999", PASS1234, "", "", "31409299")]
        public void Generate_OneWay_WithHmacSha512TruncatedTo8DigitsUsingCounterAnd8DigitsQuestion(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA512-8:C-QN08");
            var questionHex = int.Parse(question).ToString("X");

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA512-8:QN08-T1M
        [Theory]
        [InlineData(SEED64, "", "00000000", "", "", "132d0b6", "95209754")]
        [InlineData(SEED64, "", "11111111", "", "", "132d0b6", "55907591")]
        [InlineData(SEED64, "", "22222222", "", "", "132d0b6", "22048402")]
        [InlineData(SEED64, "", "33333333", "", "", "132d0b6", "24218844")]
        [InlineData(SEED64, "", "44444444", "", "", "132d0b6", "36209546")]
        public void Generate_OneWay_WithHmacSha512TruncatedTo8DigitsUsing8DigitsQuestionAndTimestamp1Minute(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA512-8:QN08-T1M");
            var questionHex = int.Parse(question).ToString("X");

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA256-8:QA08 (client/server)
        [Theory]
        [InlineData(SEED32, "", "CLI22220SRV11110", "", "", "", "28247970")]
        [InlineData(SEED32, "", "CLI22221SRV11111", "", "", "", "01984843")]
        [InlineData(SEED32, "", "CLI22222SRV11112", "", "", "", "65387857")]
        [InlineData(SEED32, "", "CLI22223SRV11113", "", "", "", "03351211")]
        [InlineData(SEED32, "", "CLI22224SRV11114", "", "", "", "83412541")]
        [InlineData(SEED32, "", "SRV11110CLI22220", "", "", "", "15510767")]
        [InlineData(SEED32, "", "SRV11111CLI22221", "", "", "", "90175646")]
        [InlineData(SEED32, "", "SRV11112CLI22222", "", "", "", "33777207")]
        [InlineData(SEED32, "", "SRV11113CLI22223", "", "", "", "95285278")]
        [InlineData(SEED32, "", "SRV11114CLI22224", "", "", "", "28934924")]
        public void Generate_MutualClientServer_WithHmacSha256TruncatedTo8DigitsUsing8CharsQuestion(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA256-8:QA08");
            var questionHex = AsHex(Encoding.UTF8.GetBytes(question));

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA512-8:QA08 (server)
        [Theory]
        [InlineData(SEED64, "", "CLI22220SRV11110", "", "", "", "79496648")]
        [InlineData(SEED64, "", "CLI22221SRV11111", "", "", "", "76831980")]
        [InlineData(SEED64, "", "CLI22222SRV11112", "", "", "", "12250499")]
        [InlineData(SEED64, "", "CLI22223SRV11113", "", "", "", "90856481")]
        [InlineData(SEED64, "", "CLI22224SRV11114", "", "", "", "12761449")]
        public void Generate_MutualServerSide_WithHmacSha256TruncatedTo8DigitsUsing8CharsQuestion(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA512-8:QA08");
            var questionHex = AsHex(Encoding.UTF8.GetBytes(question));

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA512-8:QA08-PSHA1 (client)
        [Theory]
        [InlineData(SEED64, "", "SRV11110CLI22220", PASS1234, "", "", "18806276")]
        [InlineData(SEED64, "", "SRV11111CLI22221", PASS1234, "", "", "70020315")]
        [InlineData(SEED64, "", "SRV11112CLI22222", PASS1234, "", "", "01600026")]
        [InlineData(SEED64, "", "SRV11113CLI22223", PASS1234, "", "", "18951020")]
        [InlineData(SEED64, "", "SRV11114CLI22224", PASS1234, "", "", "32528969")]
        public void Generate_MutualClientSide_WithHmacSha512TruncatedTo8DigitsUsing8CharsQuestionAndSha1Password(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA512-8:QA08-PSHA1");
            var questionHex = AsHex(Encoding.UTF8.GetBytes(question));

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA256-8:QA08
        [Theory]
        [InlineData(SEED32, "", "SIG10000", "", "", "", "53095496")]
        [InlineData(SEED32, "", "SIG11000", "", "", "", "04110475")]
        [InlineData(SEED32, "", "SIG12000", "", "", "", "31331128")]
        [InlineData(SEED32, "", "SIG13000", "", "", "", "76028668")]
        [InlineData(SEED32, "", "SIG14000", "", "", "", "46554205")]
        public void Generate_PlainSignature_WithHmacSha256TruncatedTo8DigitsUsing8CharsQuestion(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA256-8:QA08");
            var questionHex = AsHex(Encoding.UTF8.GetBytes(question));

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        // OCRA-1:HOTP-SHA512-8:QA10-T1M
        [Theory]
        [InlineData(SEED64, "", "SIG1000000", "", "", "132d0b6", "77537423")]
        [InlineData(SEED64, "", "SIG1100000", "", "", "132d0b6", "31970405")]
        [InlineData(SEED64, "", "SIG1200000", "", "", "132d0b6", "10235557")]
        [InlineData(SEED64, "", "SIG1300000", "", "", "132d0b6", "95213541")]
        [InlineData(SEED64, "", "SIG1400000", "", "", "132d0b6", "65360607")]
        public void Generate_PlainSignature_WithHmacSha512TruncatedTo8DigitsUsing8CharsQuestionAndTimestamp1Minute(string key, string counter, string question, string password, string session, string timestamp, string expectedCode)
        {
            // arrange
            var ocra = OcraGenerator.Create("OCRA-1:HOTP-SHA512-8:QA10-T1M");
            var questionHex = AsHex(Encoding.UTF8.GetBytes(question));

            // act
            var actualCode = ocra.Generate(key, counter, questionHex, password, session, timestamp);

            // assert
            Assert.Equal(expectedCode, actualCode);
        }

        public static string AsHex(byte[] buf)
        {
            var strbuf = new StringBuilder(buf.Length * 2);
            int i;

            for (i = 0; i < buf.Length; i++)
            {
                if ((buf[i] & 0xff) < 0x10)
                    strbuf.Append("0");
                strbuf.Append((buf[i] & 0xff).ToString("X"));
            }
            return strbuf.ToString();
        }

        // Sha1 hash of PIN '1234'
        private const string PASS1234 = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";

        private const string SEED20 = "3132333435363738393031323334353637383930";
        private const string SEED32 = "3132333435363738393031323334353637383930313233343536373839303132";
        private const string SEED64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
    }
}
