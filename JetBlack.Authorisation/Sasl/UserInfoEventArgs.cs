using System;

namespace JetBlack.Authorisation.Sasl
{
    /// <summary>
    /// This class provides data for server authentication mechanisms <b>GetUserInfo</b> event.
    /// </summary>
    public class UserInfoEventArgs : EventArgs
    {
        private readonly string _userName = string.Empty;
        private string _password = string.Empty;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="userName">User name.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>userName</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
        public UserInfoEventArgs(string userName)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Argument 'userName' value must be specified.", "userName");

            _userName = userName;
        }

        /// <summary>
        /// Gets or sets if specified user exists.
        /// </summary>
        public bool UserExists { get; set; }

        /// <summary>
        /// Gets user name.
        /// </summary>
        public string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Gets or sets user password.
        /// </summary>
        public string Password
        {
            get { return _password; }
            set { _password = value; }
        }
    }
}
