using System;
using System.Collections.Generic;
using System.Text;
using JetBlack.Authorisation.Utils;

namespace JetBlack.Authorisation.Sasl.Mechanism.Plain
{
    public class PlainSaslServerMechanism : PlainSaslMechanism, ISaslServerMechanism
    {
        private readonly AuthenticationDelegate _authenticationDelegate;

        public PlainSaslServerMechanism(AuthenticationDelegate authenticationDelegate)
        {
            if (authenticationDelegate == null)
                throw new ArgumentNullException("authenticationDelegate");

            _authenticationDelegate = authenticationDelegate;
        }

        public void Reset()
        {
            IsCompleted = false;
            IsAuthenticated = false;
            AuthorizationId = string.Empty;
            UserName = string.Empty;
        }

        public byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            if (clientResponse.Length == 0)
                return new byte[0];

            var parts = Encoding.UTF8.GetString(clientResponse).Split('\0');
            if (parts.Length == 3 && !string.IsNullOrEmpty(parts[1]))
            {
                AuthorizationId = parts[0].NullIfWhitespace();
                UserName = parts[1];
                IsAuthenticated = _authenticationDelegate(AuthorizationId, UserName, parts[2].NullIfWhitespace());
            }

            IsCompleted = true;

            return null;
        }

        public bool IsCompleted { get; private set; }
        public bool IsAuthenticated { get; private set; }
        public string AuthorizationId { get; private set; }
        public string UserName { get; private set; }

        public Dictionary<string, object> Tags
        {
            get { return null; }
        }
    }
}
