using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.DigestMd5
{
    public class DigestMd5SaslClientMechanism : DigestMd5SaslMechanism, ISaslClientMechanism
    {
        private readonly string _protocol;
        private readonly string _serverName;
        private readonly string _userName;
        private readonly string _password;
        private int _state;
        private DigestMd5Response _response;

        public DigestMd5SaslClientMechanism(string protocol, string server, string userName, string password)
        {
            if (protocol == null)
                throw new ArgumentNullException("protocol");
            if (protocol == string.Empty)
                throw new ArgumentException("Argument 'protocol' value must be specified.", "userName");
            if (server == null)
                throw new ArgumentNullException("protocol");
            if (server == string.Empty)
                throw new ArgumentException("Argument 'server' value must be specified.", "userName");
            if (userName == null)
                throw new ArgumentNullException("userName");
            if (userName == string.Empty)
                throw new ArgumentException("Argument 'username' value must be specified.", "userName");
            if (password == null)
                throw new ArgumentNullException("password");

            _protocol = protocol;
            _serverName = server;
            _userName = userName;
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

                // Parse server challenge.
                var challenge = DigestMd5Challenge.Parse(Encoding.UTF8.GetString(serverResponse));

                // Construct our response to server challenge.
                _response = new DigestMd5Response(
                    challenge,
                    challenge.Realm[0],
                    _userName,
                    _password,
                    Guid.NewGuid().ToString().Replace("-", ""),
                    1,
                    challenge.QopOptions[0],
                    _protocol + "/" + _serverName
                );

                return Encoding.UTF8.GetBytes(_response.ToResponse());
            }
            else if (_state == 1)
            {
                _state++;
                IsCompleted = true;

                // Check rspauth value.
                if (!string.Equals(Encoding.UTF8.GetString(serverResponse), _response.ToRspauthResponse(_userName, _password), StringComparison.InvariantCultureIgnoreCase))
                    throw new Exception("Server server 'rspauth' value mismatch with local 'rspauth' value.");

                return new byte[0];
            }
            else
            {
                throw new InvalidOperationException("Authentication is completed.");
            }
        }

        public bool IsCompleted { get; private set; }

        public string UserName
        {
            get { return _userName; }
        }

        public bool SupportsInitialResponse
        {
            get { return false; }
        }
    }
}
