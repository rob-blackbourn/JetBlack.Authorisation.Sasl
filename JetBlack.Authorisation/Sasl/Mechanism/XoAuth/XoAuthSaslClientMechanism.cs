﻿using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.XoAuth
{
    /// <summary>
    /// This class implements <b>XOAUTH</b> authentication.
    /// </summary>
    public class XoAuthSaslClientMechanism : XoAuthSaslMechanism, ISaslClientMechanism
    {
        private readonly string _userName;
        private readonly string _authString;
        private bool _isCompleted = false;
        private int _state = 0;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="userName">User login name.</param>
        /// <param name="authString">OAUTH authentication string. For example you can use <see cref="GmailOAuth1.GetXoAuthStringForImap"/> to get valid string.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>userName</b> or <b>authString</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is riased when any of the arguments has invalid value.</exception>
        public XoAuthSaslClientMechanism(string userName, string authString)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Argument 'userName' value must be specified.", "userName");
            if (string.IsNullOrEmpty(authString))
                throw new ArgumentException("Argument 'authString' value must be specified.", "authString");

            _userName = userName;
            _authString = authString;
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
            if (_isCompleted)
                throw new InvalidOperationException("Authentication is completed.");

            if (_state == 0)
            {
                _isCompleted = true;
                return Encoding.UTF8.GetBytes(_authString);
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
        /// Gets user login name.
        /// </summary>
        public string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Returns always true, because XOAUTH authentication method supports SASL client "inital response".
        /// </summary>
        public bool SupportsInitialResponse
        {
            get { return true; }
        }
    }
}
