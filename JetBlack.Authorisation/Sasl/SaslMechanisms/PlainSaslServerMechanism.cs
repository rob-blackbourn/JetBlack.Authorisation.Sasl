using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    /// <summary>
    /// Implements "PLAIN" authenticaiton. Defined in RFC 4616.
    /// </summary>
    public class PlainSaslServerMechanism : SaslServerMechanism
    {
        private bool _isCompleted = false;
        private bool _isAuthenticated = false;
        private bool _requireSSL = false;
        private string _userName = "";

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="requireSSL">Specifies if this mechanism is available to SSL connections only.</param>
        public PlainSaslServerMechanism(bool requireSSL)
        {
            _requireSSL = requireSSL;
        }

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public override void Reset()
        {
            _isCompleted = false;
            _isAuthenticated = false;
            _userName = "";
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientResponse</b> is null reference.</exception>
        /// <remarks>
        /// RFC 4616.2. PLAIN SASL Mechanism.                
        /// The mechanism consists of a single message, a string of[UTF - 8]
        /// encoded[Unicode] characters, from the client to the server.The
        /// client presents the authorization identity(identity to act as),
        /// followed by a NUL(U+0000) character, followed by the authentication
        /// identity(identity whose password will be used), followed by a NUL
        /// (U+0000) character, followed by the clear-text password.As with
        /// other SASL mechanisms, the client does not provide an authorization
        /// identity when it wishes the server to derive an identity from the
        /// credentials and use that as the authorization identity.
        ///
        /// message   = [authzid] UTF8NUL authcid UTF8NUL passwd
        ///
        /// Example:
        ///     C: a002 AUTHENTICATE "PLAIN"
        ///     S: + ""
        ///     C: { 21}
        ///     C: <NUL>tim<NUL> tanstaaftanstaaf
        ///     S: a002 OK "Authenticated"
        /// </remarks>
        public override byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            if (clientResponse.Length == 0)
                return new byte[0];

            string[] authzid_authcid_passwd = Encoding.UTF8.GetString(clientResponse).Split('\0');
            if (authzid_authcid_passwd.Length == 3 && !string.IsNullOrEmpty(authzid_authcid_passwd[1]))
            {
                _userName = authzid_authcid_passwd[1];
                AuthenticateEventArgs result = OnAuthenticate(authzid_authcid_passwd[0], authzid_authcid_passwd[1], authzid_authcid_passwd[2]);
                _isAuthenticated = result.IsAuthenticated;
            }

            _isCompleted = true;

            return null;
        }

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public override bool IsCompleted
        {
            get { return _isCompleted; }
        }

        /// <summary>
        /// Gets if user has authenticated sucessfully.
        /// </summary>
        public override bool IsAuthenticated
        {
            get { return _isAuthenticated; }
        }

        /// <summary>
        /// Returns always "PLAIN".
        /// </summary>
        public override string Name
        {
            get { return "PLAIN"; }
        }

        /// <summary>
        /// Gets if specified SASL mechanism is available only to SSL connection.
        /// </summary>
        public override bool RequireSSL
        {
            get { return _requireSSL; }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public override string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Is called when authentication mechanism needs to authenticate specified user.
        /// </summary>
        public event EventHandler<AuthenticateEventArgs> Authenticate = null;

        /// <summary>
        /// Raises <b>Authenticate</b> event.
        /// </summary>
        /// <param name="authorizationID">Authorization ID.</param>
        /// <param name="userName">User name.</param>
        /// <param name="password">Password.</param>
        /// <returns>Returns authentication result.</returns>
        private AuthenticateEventArgs OnAuthenticate(string authorizationID, string userName, string password)
        {
            var retVal = new AuthenticateEventArgs(authorizationID, userName, password);

            if (Authenticate != null)
                Authenticate(this, retVal);

            return retVal;
        }
    }
}
