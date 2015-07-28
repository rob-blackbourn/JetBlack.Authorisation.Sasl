using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.DigestMd5
{
    /// <summary>
    /// Implements "DIGEST-MD5" authenticaiton.
    /// </summary>
    public class DigestMd5SaslClientMechanism : DigestMd5SaslMechanism, ISaslClientMechanism
    {
        private readonly string _protocol;
        private readonly string _serverName;
        private readonly string _userName;
        private readonly string _password;
        private int _state;
        private DigestMd5Response _response;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="protocol">Protocol name. For example: SMTP.</param>
        /// <param name="server">Remote server name or IP address.</param>
        /// <param name="userName">User login name.</param>
        /// <param name="password">User password.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>protocol</b>,<b>server</b>,<b>userName</b> or <b>password</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
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

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="serverResponse">Server sent SASL response.</param>
        /// <returns>Returns challange request what must be sent to server or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>serverResponse</b> is null reference.</exception>
        /// <exception cref="InvalidOperationException">Is raised when this method is called when authentication is completed.</exception>
        /// <remarks>
        /// RFC 2831.
        /// The base64-decoded version of the SASL exchange is:
        /// 
        /// S: realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",
        ///    algorithm=md5-sess,charset=utf-8
        /// C: charset=utf-8,username="chris",realm="elwood.innosoft.com",
        ///    nonce="OA6MG9tEQGm2hh",nc=00000001,cnonce="OA6MHXh6VqTrRk",
        ///    digest-uri="imap/elwood.innosoft.com",
        ///    response=d388dad90d4bbd760a152321f2143af7,qop=auth
        /// S: rspauth=ea40f60335c427b5527b84dbabcdfffd
        /// C: 
        /// S: ok
        /// 
        /// The password in this example was "secret".
        /// </remarks>
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

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public bool IsCompleted { get; private set; }

        /// <summary>
        /// Gets user login name.
        /// </summary>
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
