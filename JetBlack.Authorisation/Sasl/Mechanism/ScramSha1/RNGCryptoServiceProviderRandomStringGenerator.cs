using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.ScramSha1
{
    internal class RNGCryptoServiceProviderRandomStringGenerator : IRandomStringGenerator
    {
        public string Generate(int length, string legalCharacters)
        {
            var randomData = new byte[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomData);
            }

            var randonCharacters = new char[length];
            randomData.ForEach

            var sb = new StringBuilder(length);
            for (var i = 0; i < length; ++i)
            {
                var pos = randomData[i] % legalCharacters.Length;
                sb.Append(legalCharacters[pos]);
            }

            return sb.ToString();
        }
    }

    public static class LinqExtensions
    {
        
    }
}
