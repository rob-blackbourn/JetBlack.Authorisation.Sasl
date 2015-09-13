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
			var randomBytes = new byte[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }

            var randomChars = new char[length];
			randomBytes.ForEach ((b, i) => {
				randomChars[i] = legalCharacters[b % legalCharacters.Length];
			});

			return new string (randomChars);
        }
    }
}
