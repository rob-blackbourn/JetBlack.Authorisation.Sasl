using System;
using System.Security.Cryptography;
using System.Text;
using JetBlack.Authorisation.Utils;

namespace JetBlack.Authorisation.Sasl.Mechanism.CramMd5
{
    public class CramMd5SaslClientMechanism : CramMd5SaslMechanism, ISaslClientMechanism
    {
        private readonly string _password;
        private int _state;

        public CramMd5SaslClientMechanism(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Value must be specified.", "userName");
            if (password == null)
                throw new ArgumentNullException("password");

            UserName = userName;
            _password = password;
        }

        public byte[] Continue(byte[] serverResponse)
        {
            if (serverResponse == null)
                throw new ArgumentNullException("serverResponse");
            if (IsCompleted)
                throw new InvalidOperationException("Authentication is completed.");

            if (_state == 0)
            {
                ++_state;
                IsCompleted = true;

                var kMd5 = new HMACMD5(Encoding.UTF8.GetBytes(_password));
                var passwordHash = NetUtils.ToHex(kMd5.ComputeHash(serverResponse)).ToLower();
                return Encoding.UTF8.GetBytes(string.Concat(UserName, ' ', passwordHash));
            }

            throw new InvalidOperationException("Authentication is completed.");
        }

        public bool IsCompleted { get; private set; }

        public string UserName{ get; private set; }

        public bool SupportsInitialResponse
        {
            get { return false; }
        }
    }
}
