using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using JetBlack.Authorisation.Utils;

namespace JetBlack.Authorisation.Sasl.Mechanism.CramMd5
{
    public class CramMd5SaslServerMechanism : CramMd5SaslMechanism, ISaslServerMechanism
    {
        private readonly UserInfoDelegate _userInfoDelegate;
        private readonly string _hostName;
        private int _state = 0;
        private string _key = "";

        public CramMd5SaslServerMechanism(UserInfoDelegate userInfoDelegate, string hostName)
        {
            if (userInfoDelegate == null)
                throw new ArgumentNullException("userInfoDelegate");

            _userInfoDelegate = userInfoDelegate;
            _hostName = hostName;
        }

        public void Reset()
        {
            IsCompleted = false;
            IsAuthenticated = false;
            _state = 0;
            _key = "";
        }

        public byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            if (_state == 0)
            {
                ++_state;
                _key = string.Concat('<', Guid.NewGuid(), '@', _hostName, '>');
                return Encoding.UTF8.GetBytes(_key);
            }
            
            if (_state == 1)
            {
                // Parse client response. response = userName SP hash.
                var parts = Encoding.UTF8.GetString(clientResponse).Split(' ');
                if (parts.Length == 2 && !string.IsNullOrEmpty(parts[0]))
                {
                    UserName = parts[0];
                    var userInfo = _userInfoDelegate(UserName);
                    if (userInfo.UserExists)
                    {
                        var hash = NetUtils.ToHex(HmacMd5(_key, userInfo.Password));
                        IsAuthenticated = (hash == parts[1]);
                    }
                }

                IsCompleted = true;
            }

            return null;
        }

        private static byte[] HmacMd5(string hashKey, string text)
        {
            var kMd5 = new HMACMD5(Encoding.Default.GetBytes(text));
            return kMd5.ComputeHash(Encoding.ASCII.GetBytes(hashKey));
        }

        public bool IsCompleted { get; private set; }
        public bool IsAuthenticated { get; private set; }
        public string UserName { get; private set; }
        public Dictionary<string, object> Tags { get { return null; } }
    }
}
