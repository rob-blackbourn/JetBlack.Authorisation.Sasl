using System;
using System.Collections.Generic;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.Login
{
    /// <summary>
    /// Implements "LOGIN" authenticaiton.
    /// </summary>
    public class LoginSaslServerMechanism : LoginSaslMechanism, ISaslServerMechanism
    {
        private readonly AuthenticationDelegate _authenticationDelegate;
        private string _password;
        private int _state;

        public LoginSaslServerMechanism(AuthenticationDelegate authenticationDelegate)
        {
            _authenticationDelegate = authenticationDelegate;
        }

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public void Reset()
        {
            IsCompleted = false;
            IsAuthenticated = false;
            UserName = null;
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
            
            if (_state == 1)
            {
                ++_state;
                UserName = Encoding.UTF8.GetString(clientResponse);

                return Encoding.ASCII.GetBytes("Password:");
            }

            if (_state == 2)
            {
                _password = Encoding.UTF8.GetString(clientResponse);
                IsAuthenticated = _authenticationDelegate(null, UserName, _password);
                IsCompleted = true;
            }

            return null;
        }

        public bool IsCompleted { get; private set; }
        public bool IsAuthenticated { get; private set; }
        public string UserName { get; private set; }
        public Dictionary<string, object> Tags { get { return null; } }
    }
}
