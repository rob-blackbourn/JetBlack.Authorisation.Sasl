using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.Plain
{
    public class PlainSaslClientMechanism : PlainSaslMechanism, ISaslClientMechanism
    {
        private readonly string _password;

        private int _state;

        public PlainSaslClientMechanism(string authorizationId, string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Argument 'username' value must be specified.", "userName");
            if (password == null)
                throw new ArgumentNullException("password");

            AuthorizationId = authorizationId;
            UserName = userName;
            _password = password;
        }

        public byte[] Continue(byte[] serverResponse)
        {
            if (IsCompleted)
                throw new InvalidOperationException("Authentication is completed.");

            if (_state == 0)
            {
                ++_state;
                IsCompleted = true;

                return Encoding.UTF8.GetBytes(string.Concat(AuthorizationId ?? string.Empty, '\0', UserName, '\0', _password));
            }
            
            throw new InvalidOperationException("Authentication is completed.");
        }

        public bool IsCompleted { get; private set; }
        public string AuthorizationId { get; private set; }
        public string UserName { get; private set; }
        public bool SupportsInitialResponse { get { return true; } }
    }
}
