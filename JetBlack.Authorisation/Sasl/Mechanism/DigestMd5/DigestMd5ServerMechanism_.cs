using System;
using System.Collections.Generic;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.DigestMd5
{
    public class DigestMd5SaslServerMechanism : DigestMd5SaslMechanism, ISaslServerMechanism
    {
        private readonly UserInfoDelegate _userInfoDelegate;
        private string _realm = string.Empty;
        private readonly string _nonce;
        private string _userName = string.Empty;
        private int _state;

        public DigestMd5SaslServerMechanism(UserInfoDelegate userInfoDelegate)
        {
            _userInfoDelegate = userInfoDelegate;
            _nonce = HttpDigest.CreateNonce();
        }

        public void Reset()
        {
            IsCompleted = false;
            IsAuthenticated = false;
            _userName = "";
            _state = 0;
        }

        public byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            if (_state == 0)
            {
                ++_state;

                var callenge = new DigestMd5Challenge(new[] { _realm }, _nonce, new[] { "auth" }, false);

                return Encoding.UTF8.GetBytes(callenge.ToChallenge());
            }
            else if (_state == 1)
            {
                ++_state;

                try
                {
                    var response = DigestMd5Response.Parse(Encoding.UTF8.GetString(clientResponse));

                    // Check realm and nonce value.
                    if (_realm != response.Realm || _nonce != response.Nonce)
                        return Encoding.UTF8.GetBytes("rspauth=\"\"");

                    _userName = response.UserName;
                    var userInfo = _userInfoDelegate(response.UserName);
                    if (userInfo.UserExists)
                    {
                        if (response.Authenticate(userInfo.UserName, userInfo.Password))
                        {
                            IsAuthenticated = true;

                            return Encoding.UTF8.GetBytes(response.ToRspauthResponse(userInfo.UserName, userInfo.Password));
                        }
                    }
                }
                catch
                {
                    // Authentication failed, just reject request.
                }

                return Encoding.UTF8.GetBytes("rspauth=\"\"");
            }
            else
            {
                IsCompleted = true;
            }

            return null;
        }

        public bool IsCompleted { get; private set; }

        public bool IsAuthenticated { get; private set; }

        public string Realm
        {
            get { return _realm; }
            set
            {
                _realm = value ?? string.Empty;
            }
        }

        public string UserName
        {
            get { return _userName; }
        }

        public Dictionary<string, object> Tags { get { return null; } }
    }
}
