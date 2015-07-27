using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Server.Mechanisms
{
    /// <summary>
    /// Implements "LOGIN" authenticaiton.
    /// </summary>
    public class LoginServerMechanism : ServerMechanism
    {
        private bool _isCompleted = false;
        private bool _isAuthenticated = false;
        private bool _requireSSL = false;
        private string _userName = null;
        private string _password = null;
        private int _state = 0;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="requireSSL">Specifies if this mechanism is available to SSL connections only.</param>
        public LoginServerMechanism(bool requireSSL)
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
            _userName = null;
            _password = null;
            _state = 0;
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
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
        public override byte[] Continue(byte[] clientResponse)
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
        /// Returns always "LOGIN".
        /// </summary>
        public override string Name
        {
            get { return "LOGIN"; }
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

            if (this.Authenticate != null)
                this.Authenticate(this, retVal);

            return retVal;
        }
    }
}
