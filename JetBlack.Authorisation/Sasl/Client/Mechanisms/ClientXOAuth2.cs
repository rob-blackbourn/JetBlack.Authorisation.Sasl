﻿using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Client.Mechanisms
{
    /// <summary>
    /// This class implements <b>XOAUTH2</b> authentication.
    /// </summary>
    public class ClientXoAuth2 : ClientMechanism
    {
        private readonly string _userName;
        private readonly string _accessToken;
        private bool _isCompleted = false;
        private int _state = 0;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="userName">User login name.</param>
        /// <param name="accessToken">The access Token.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>userName</b> or <b>accessToken</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
        public ClientXoAuth2(string userName, string accessToken)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Argument 'userName' value must be specified.", "userName");
            }
            if (string.IsNullOrEmpty(accessToken))
                throw new ArgumentException("Argument 'accessToken' value must be specified.", "accessToken");

            _userName = userName;
            _accessToken = accessToken;
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="serverResponse">Server sent SASL response.</param>
        /// <returns>Returns challange request what must be sent to server or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>serverResponse</b> is null reference.</exception>
        /// <exception cref="InvalidOperationException">Is raised when this method is called when authentication is completed.</exception>
        public override byte[] Continue(byte[] serverResponse)
        {
            if (_isCompleted)
                throw new InvalidOperationException("Authentication is completed.");

            if (_state == 0)
            {
                _isCompleted = true;
                var initialClientResponse = "user=" + _userName + "\u0001auth=Bearer " + _accessToken + "\u0001\u0001";
                return Encoding.UTF8.GetBytes(initialClientResponse);
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
        /// Returns always "LOGIN".
        /// </summary>
        public override string Name
        {
            get { return "XOAUTH2"; }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public override string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Returns always true, because XOAUTH2 authentication method supports SASL client "inital response".
        /// </summary>
        public override bool SupportsInitialResponse
        {
            get { return true; }
        }
    }
}
