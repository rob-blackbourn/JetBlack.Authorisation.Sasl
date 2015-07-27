using System;
using System.Collections.Generic;
using System.Text;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    /// <summary>
    /// Implements "LOGIN" authenticaiton.
    /// </summary>
    public class LoginSaslServerMechanism : LoginSaslMechanism, ISaslServerMechanism
    {
        private bool _isCompleted;
        private bool _isAuthenticated;
        private readonly bool _requireSsl;
        private string _userName;
        private string _password;
        private int _state;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="requireSsl">Specifies if this mechanism is available to SSL connections only.</param>
        public LoginSaslServerMechanism(bool requireSsl)
        {
            _requireSsl = requireSsl;
        }

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public void Reset()
        {
            _isCompleted = false;
            _isAuthenticated = false;
            _userName = null;
            _password = null;
            _state = 0;
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Returns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientResponse</b> is null reference.</exception>
        /// <remarks>
        /// RFC none.
        ///    S: "Username:"
        ///    C: userName
        ///    S: "Password:"
        ///    C: password
        ///
        /// NOTE: UserName may be included in initial client response.
        /// </remarks>
        public byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            // User name provided, so skip that state.
            if (_state == 0 && clientResponse.Length > 0)
                ++_state;

            if (_state == 0)
            {
                ++_state;

                return Encoding.ASCII.GetBytes("UserName:");
            }
            else if (_state == 1)
            {
                ++_state;
                _userName = Encoding.UTF8.GetString(clientResponse);

                return Encoding.ASCII.GetBytes("Password:");
            }
            else
            {
                _password = Encoding.UTF8.GetString(clientResponse);

                AuthenticateEventArgs result = OnAuthenticate("", _userName, _password);
                _isAuthenticated = result.IsAuthenticated;
                _isCompleted = true;
            }

            return null;
        }

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public bool IsCompleted
        {
            get { return _isCompleted; }
        }

        /// <summary>
        /// Gets if user has authenticated sucessfully.
        /// </summary>
        public bool IsAuthenticated
        {
            get { return _isAuthenticated; }
        }

        /// <summary>
        /// Gets if specified SASL mechanism is available only to SSL connection.
        /// </summary>
        public bool RequireSSL
        {
            get { return _requireSsl; }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public string UserName
        {
            get { return _userName; }
        }

        public Dictionary<string, object> Tags { get { return null; } }

        /// <summary>
        /// Is called when authentication mechanism needs to authenticate specified user.
        /// </summary>
        public event EventHandler<AuthenticateEventArgs> Authenticate = null;

        /// <summary>
        /// Raises <b>Authenticate</b> event.
        /// </summary>
        /// <param name="authorizationId">Authorization ID.</param>
        /// <param name="userName">User name.</param>
        /// <param name="password">Password.</param>
        /// <returns>Returns authentication result.</returns>
        private AuthenticateEventArgs OnAuthenticate(string authorizationId, string userName, string password)
        {
            var retVal = new AuthenticateEventArgs(authorizationId, userName, password);

            if (Authenticate != null)
                Authenticate(this, retVal);

            return retVal;
        }
    }
}
