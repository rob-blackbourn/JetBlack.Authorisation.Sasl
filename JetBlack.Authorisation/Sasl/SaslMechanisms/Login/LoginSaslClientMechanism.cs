using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms.Login
{
    /// <summary>
    /// Implements "LOGIN" authenticaiton.
    /// </summary>
    public class LoginSaslClientMechanism : LoginSaslMechanism, ISaslClientMechanism
    {
        private readonly string _userName;
        private readonly string _password;
        private bool _isCompleted;
        private int _state;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="userName">User login name.</param>
        /// <param name="password">User password.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>userName</b> or <b>password</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
        public LoginSaslClientMechanism(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Argument 'username' value must be specified.", "userName");
            if (password == null)
                throw new ArgumentNullException("password");

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
        public byte[] Continue(byte[] serverResponse)
        {
            if (serverResponse == null)
                throw new ArgumentNullException("serverResponse");
            if (_isCompleted)
                throw new InvalidOperationException("Authentication is completed.");

            /* RFC none.
                S: "Username:"
                C: userName
                S: "Password:"
                C: password
             
                NOTE: UserName may be included in initial client response.
            */

            if (_state == 0)
            {
                ++_state;
                return Encoding.UTF8.GetBytes(_userName);
            }
            
            if (_state == 1)
            {
                ++_state;
                _isCompleted = true;
                return Encoding.UTF8.GetBytes(_password);
            }
            
            throw new InvalidOperationException("Authentication is completed.");
        }

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public bool IsCompleted
        {
            get { return _isCompleted; }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public string UserName
        {
            get { return _userName; }
        }

        public bool SupportsInitialResponse { get { return false; } }
    }
}
