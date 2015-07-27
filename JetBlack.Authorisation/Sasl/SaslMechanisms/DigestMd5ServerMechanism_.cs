using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    /// <summary>
    /// Implements "DIGEST-MD5" authenticaiton. Defined in RFC 2831.
    /// </summary>
    public class DigestMd5SaslServerMechanism : SaslServerMechanism
    {
        private bool _isCompleted;
        private bool _isAuthenticated;
        private readonly bool _requireSsl;
        private string _realm = string.Empty;
        private readonly string _nonce;
        private string _userName = string.Empty;
        private int _state;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="requireSsl">Specifies if this mechanism is available to SSL connections only.</param>
        public DigestMd5SaslServerMechanism(bool requireSsl)
        {
            _requireSsl = requireSsl;
            _nonce = HttpDigest.CreateNonce();
        }

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public override void Reset()
        {
            _isCompleted = false;
            _isAuthenticated = false;
            _userName = "";
            _state = 0;
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientResponse</b> is null reference.</exception>
        /// <remarks>
        /// RFC 2831.
        /// The base64-decoded version of the SASL exchange is:
        ///
        /// S: realm="elwood.innosoft.com",
        ///    nonce="OA6MG9tEQGm2hh",
        ///    qop="auth",
        ///    algorithm=md5-sess,
        ///    charset=utf-8
        /// C: charset=utf-8,
        ///    username="chris",
        ///    realm="elwood.innosoft.com",
        ///    nonce="OA6MG9tEQGm2hh",
        ///    nc=00000001,
        ///    cnonce="OA6MHXh6VqTrRk",
        ///    digest-uri="imap/elwood.innosoft.com",
        ///    response=d388dad90d4bbd760a152321f2143af7,
        ///    qop=auth
        /// S: rspauth=ea40f60335c427b5527b84dbabcdfffd
        /// C: 
        /// S: ok
        ///
        /// The password in this example was "secret".
        /// </remarks>
        public override byte[] Continue(byte[] clientResponse)
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
                    var result = OnGetUserInfo(response.UserName);
                    if (result.UserExists)
                    {
                        if (response.Authenticate(result.UserName, result.Password))
                        {
                            _isAuthenticated = true;

                            return Encoding.UTF8.GetBytes(response.ToRspauthResponse(result.UserName, result.Password));
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
        /// Returns always "DIGEST-MD5".
        /// </summary>
        public override string Name
        {
            get { return "DIGEST-MD5"; }
        }

        /// <summary>
        /// Gets if specified SASL mechanism is available only to SSL connection.
        /// </summary>
        public override bool RequireSSL
        {
            get { return _requireSsl; }
        }

        /// <summary>
        /// Gets or sets realm value.
        /// </summary>
        /// <remarks>Normally this is host or domain name.</remarks>
        public string Realm
        {
            get { return _realm; }
            set
            {
                _realm = value ?? string.Empty;
            }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public override string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Is called when authentication mechanism needs to get user info to complete atuhentication.
        /// </summary>
        public event EventHandler<UserInfoEventArgs> GetUserInfo = null;

        /// <summary>
        /// Raises <b>GetUserInfo</b> event.
        /// </summary>
        /// <param name="userName">User name.</param>
        /// <returns>Returns specified user info.</returns>
        private UserInfoEventArgs OnGetUserInfo(string userName)
        {
            UserInfoEventArgs retVal = new UserInfoEventArgs(userName);

            if (this.GetUserInfo != null)
            {
                this.GetUserInfo(this, retVal);
            }

            return retVal;
        }
    }
}
