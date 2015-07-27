using System;
using System.Security.Cryptography;
using System.Text;

namespace JetBlack.Authorisation.Utils
{
    /// <summary>
    /// Common utility methods.
    /// </summary>
    public class NetUtils
    {
        /// <summary>
        /// Convert array elements to string.
        /// </summary>
        /// <param name="values">String values.</param>
        /// <param name="delimiter">Values delimiter.</param>
        /// <returns>Returns array elements as string.</returns>
        public static string ArrayToString(string[] values, string delimiter)
        {
            if (values == null)
                return string.Empty;

            var retVal = new StringBuilder();
            for (var i = 0; i < values.Length; ++i)
            {
                if (i > 0)
                    retVal.Append(delimiter);
                retVal.Append(values[i]);
            }

            return retVal.ToString();
        }

        /// <summary>
		/// Converts specified data to HEX string.
		/// </summary>
		/// <param name="data">Data to convert.</param>
		/// <returns>Returns hex string.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>data</b> is null reference.</exception>
		public static string ToHex(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return BitConverter.ToString(data).ToLower().Replace("-", "");
        }

        /// <summary>
        /// Computes md5 hash.
        /// </summary>
        /// <param name="text">Text to hash.</param>
        /// <param name="hex">Specifies if md5 value is returned as hex string.</param>
        /// <returns>Returns md5 value or md5 hex value.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>text</b> is null reference.</exception>
        public static string ComputeMd5(string text, bool hex)
        {
            if (text == null)
                throw new ArgumentNullException("text");

            MD5 md5 = new MD5CryptoServiceProvider();
            var hash = md5.ComputeHash(Encoding.Default.GetBytes(text));

            return hex ? ToHex(hash).ToLower() : Encoding.Default.GetString(hash);
        }
    }
}
