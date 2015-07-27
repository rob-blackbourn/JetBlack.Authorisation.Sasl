using System;

namespace JetBlack.Authorisation
{
    /// <summary>
    /// This class provides data for server userName/password authentications.
    /// </summary>
    public class AuthenticateEventArgs : EventArgs
    {
        private readonly string _authorizationId = "";
        private readonly string _userName = "";
        private readonly string _password = "";

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="authorizationId">Authorization ID.</param>
        /// <param name="userName">User name.</param>
        /// <param name="password">Password.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>userName</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the argumnets has invalid value.</exception>
        public AuthenticateEventArgs(string authorizationId, string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Argument 'userName' value must be specified.", "userName");

            _authorizationId = authorizationId;
            _userName = userName;
            _password = password;
        }

        /// <summary>
        /// Gets or sets if specified user is authenticated.
        /// </summary>
        public bool IsAuthenticated { get; set; }

        /// <summary>
        /// Gets authorization ID.
        /// </summary>
        public string AuthorizationId
        {
            get { return _authorizationId; }
        }

        /// <summary>
        /// Gets user name.
        /// </summary>
        public string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Gets password.
        /// </summary>
        public string Password
        {
            get { return _password; }
        }
    }
}
