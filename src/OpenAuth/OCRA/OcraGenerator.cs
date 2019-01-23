using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Lsquared.Extensions.OpenAuth.Internals;

namespace Lsquared.Extensions.OpenAuth.OCRA
{
    /// <summary>
    /// Represents the OCRA generator defined in RFC-6287.
    /// </summary>
    /// <remarks>
    /// Based on RFC-6287 [https://tools.ietf.org/html/rfc6287].
    /// </remarks>
    public class OcraGenerator
    {
        /// <summary>
        /// Creates a new instance of <see cref="OcraGenerator"/>.
        /// </summary>
        /// <param name="parameters">The options to use to generate codes.</param>
        private OcraGenerator(OcraParameters parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (parameters.CodeLength < 4 && parameters.CodeLength != 0)
                throw new ArgumentException("", nameof(parameters));
            if (parameters.CodeLength > 9)
                throw new ArgumentException("", nameof(parameters));
            _parameters = parameters;
        }

        /// <summary>
        /// Creates an instance of <see cref="OcraGenerator"/> with the specified OCRA-suite.
        /// </summary>
        /// <param name="suite">The OCRA suite.</param>
        /// <returns>
        /// An instance of <see cref="OcraGenerator"/>.
        /// </returns>
        public static OcraGenerator Create(string suite)
        {
            if (suite == null)
                throw new ArgumentNullException(nameof(suite));

            var suite2 = suite.ToLowerInvariant();

            var parts = suite2.Split(':');
            if (parts.Length != 3)
                throw new InvalidOperationException("OCRA components");

            var version = parts[0];
            if (version != "ocra-1")
                throw new NotSupportedException("Only version 1 of OCRA is supported");

            (var digits, CryptoFunction cryptoFunction) = CreateCryptoFunction(parts[1]);

            OcraParameters parameters = Parse(parts[2]);
            parameters.Suite = suite;
            parameters.CodeLength = digits;
            parameters.Hash = cryptoFunction;
            return new OcraGenerator(parameters);
        }

        /// <summary>
        /// Generates a new code.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="question">The question.</param>
        /// <returns>
        /// A string representation of a X-digits code/PIN.
        /// </returns>
        public string Generate(string privateKey, string question) =>
            Generate(privateKey, "", question, "", "", "");

        /// <summary>
        /// Generates a new code.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="counter">The counter.</param>
        /// <param name="question">The question.</param>
        /// <returns>
        /// A string representation of a X-digits code/PIN.
        /// </returns>
        public string Generate(string privateKey, string counter, string question) =>
            Generate(privateKey, counter, question, "", "", "");

        /// <summary>
        /// Generates a new code.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="counter">The counter.</param>
        /// <param name="question">The question.</param>
        /// <param name="password">The password.</param>
        /// <returns>
        /// A string representation of a X-digits code/PIN.
        /// </returns>
        public string Generate(string privateKey, string counter, string question, string password) =>
            Generate(privateKey, counter, question, password, "", "");

        // TODO make counter an integer?
        // TODO convert question to hex based on suite/parameters
        // TODO make password a byte[]?
        // TODO make timestamp a DateTimeOffset + convert to time step from suite/parameters (T1M = 1 minute)
        /// <summary>
        /// Generates a new code.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="counter">The counter.</param>
        /// <param name="question">The question.</param>
        /// <param name="password">The password.</param>
        /// <param name="session">The session.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>
        /// A string representation of a X-digits code/PIN.
        /// </returns>
        public string Generate(string privateKey, string counter, string question, string password, string session, string timestamp)
        {
            if (privateKey is null)
                throw new ArgumentNullException(nameof(privateKey));

            if (privateKey.Length == 0 || privateKey.Length % 2 != 0)
                throw new ArgumentException(nameof(privateKey));

            if (_parameters.CounterLength > 0 && string.IsNullOrEmpty(counter))
                throw new ArgumentException("Mandatory", nameof(counter));

            if (_parameters.QuestionLength > 0 && string.IsNullOrEmpty(question))
                throw new ArgumentException("Mandatory", nameof(question));

            if (_parameters.PasswordLength > 0 && string.IsNullOrEmpty(password))
                throw new ArgumentException("Mandatory", nameof(password));

            if (_parameters.PasswordLength > 0 && password.Length != _parameters.PasswordLength * 2)
                throw new ArgumentException("Bad length", nameof(password));

            if (_parameters.SessionLength > 0 && string.IsNullOrEmpty(session))
                throw new ArgumentException("Mandatory", nameof(session));

            if (_parameters.TimestampLength > 0 && string.IsNullOrEmpty(timestamp))
                throw new ArgumentException("Mandatory", nameof(timestamp));

            var buffer = CreateMessage(counter, question, password, session, timestamp, _parameters);
            var privateKeyBytes = HexToBytes(privateKey);
            var hash = _parameters.Hash(privateKeyBytes, buffer);

            var code = ComputeDigits(hash);
            return code;
        }

        #region Helpers

        private byte[] CreateMessage(
            string counter, string question, string password,
            string session, string timestamp, OcraParameters parameters)
        {
            var suiteBytes = Encoding.UTF8.GetBytes(_parameters.Suite);

            // Remember to add "1" for the "00" byte delimiter
            var result = new byte[
                suiteBytes.Length +
                1 +
                parameters.CounterLength +
                parameters.QuestionLength +
                parameters.PasswordLength +
                parameters.SessionLength +
                parameters.TimestampLength];

            // Put the bytes of the "suite" into the message
            Array.Copy(suiteBytes, 0, result, 0, suiteBytes.Length);

            // Delimiter
            result[suiteBytes.Length] = 0x00;

            byte[] tmp;
            var index = suiteBytes.Length + 1;

            // Put the bytes of "Counter" to the message
            // Input is HEX encoded
            if (parameters.CounterLength > 0)
            {
                counter = counter.PadLeft(_parameters.CounterLength * 2, '0');
                tmp = HexToBytes(counter);
                Array.Copy(tmp, 0, result, index, tmp.Length);
                index += parameters.CounterLength;
            }

            // Put the bytes of "question" to the message
            // Input is text encoded
            if (parameters.QuestionLength > 0)
            {
                question = question.PadRight(_parameters.QuestionLength * 2, '0');
                tmp = HexToBytes(question);
                Array.Copy(tmp, 0, result, index, tmp.Length);
                index += parameters.QuestionLength;
            }

            // Put the bytes of "password" to the message
            // Input is HEX encoded
            if (parameters.PasswordLength > 0)
            {
                // Next line is not needed: https://www.rfc-editor.org/errata_search.php?rfc=6287
                // password = password.PadLeft(_parameters.PasswordLength * 2, '0');
                tmp = HexToBytes(password);
                Array.Copy(tmp, 0, result, index, tmp.Length);
                index += parameters.PasswordLength;
            }

            // Put the bytes of "sessionInformation" to the message
            // Input is text encoded
            if (parameters.SessionLength > 0)
            {
                session = session.PadLeft(_parameters.SessionLength * 2, '0');
                tmp = HexToBytes(session);
                Array.Copy(tmp, 0, result, index, tmp.Length);
                index += parameters.SessionLength;
            }

            // Put the bytes of "time" to the message
            // Input is HEX encoded value of minutes
            if (parameters.TimestampLength > 0)
            {
                timestamp = timestamp.PadLeft(_parameters.TimestampLength * 2, '0');
                tmp = HexToBytes(timestamp);
                Array.Copy(tmp, 0, result, index, tmp.Length);
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private string ComputeDigits(byte[] hash)
        {
            // Same code as in OtpGenerator.
            var binaryCode = OtpHelpers.TruncateHash(hash);
            var otpCode = OtpHelpers.DoBinaryCodeReduction(binaryCode, _parameters.CodeLength);
            return otpCode.ToString(CultureInfo.InvariantCulture).PadLeft(_parameters.CodeLength, '0');
        }

        private static (int digits, CryptoFunction) CreateCryptoFunction(string cryptoFunction)
        {
            var parts = cryptoFunction.Split('-');

            var mode = parts[0];
            var partialHashName = parts[1];
            var length = parts[2];

            if (mode == "hotp")
            {
                var digits = int.Parse(length);
                return (digits, (privateKey, buffer) =>
                {
                    using (var hmac = HMAC.Create(GetHashName(partialHashName)))
                    {
                        hmac.Key = privateKey;
                        return hmac.ComputeHash(buffer);
                    }
                }
                );
            }
            else
            {
                throw new InvalidOperationException("Only HOTP is valid for cryptographic function");
            }
        }

        private static OcraParameters Parse(string value)
        {
            // Computes the size of the byte array message to be encrypted
            var counterLength = 0;
            var questionLength = 0;
            var passwordLength = 0;
            var sessionLength = 0;
            var timestampLength = 0;

            value = value.ToLowerInvariant();

            // Counter
            if (value.StartsWith("c"))
            {
                counterLength = 8;
            }

            // Question
            if (value.StartsWith("q") || (value.IndexOf("-q") >= 0))
            {
                questionLength = 128;
            }

            // Password
            if (value.IndexOf("psha1") > 1)
            {
                // sha1
                passwordLength = 20;
            }
            else if (value.IndexOf("psha256") > 1)
            {
                // sha256
                passwordLength = 32;
            }
            else if (value.IndexOf("psha512") > 1)
            {
                // sha512
                passwordLength = 64;
            }

            // Session
            if (value.IndexOf("s064") > 1)
            {
                sessionLength = 64;
            }
            else if (value.IndexOf("s128") > 1)
            {
                sessionLength = 128;
            }
            else if (value.IndexOf("s256") > 1)
            {
                sessionLength = 256;
            }
            else if (value.IndexOf("s512") > 1)
            {
                sessionLength = 512;
            }

            // Timestamp
            if (value.StartsWith("t") || (value.IndexOf("-t") > 1))
            {
                timestampLength = 8;
            }

            return new OcraParameters
            {
                CounterLength = counterLength,
                PasswordLength = passwordLength,
                QuestionLength = questionLength,
                SessionLength = sessionLength,
                TimestampLength = timestampLength
            };
        }

        private static string GetHashName(string partialHashName)
        {
            switch (partialHashName)
            {
                case "sha1": return "HMACSHA1";
                case "sha256": return "HMACSHA256";
                case "sha512": return "HMACSHA512";
                default: throw new InvalidOperationException();
            }
        }

        // Code from 
        private static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex))
                throw new ArgumentNullException(nameof(hex));
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Length must be even", nameof(hex));

            var len = hex.Length >> 1; // initial length of result
            var result = new byte[len];

            for (var i = 0; i < len; i++)
            {
                result[i] = (byte)(ToByte(hex[i * 2], hex) * 16 + ToByte(hex[i * 2 + 1], hex));
            }

            return result;

            byte ToByte(char c, string value)
            {
                var s = c.ToString();
                var b = byte.Parse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                return b;
            }
        }

        #endregion

        #region Fields

        private readonly OcraParameters _parameters;

        #endregion
    }
}
