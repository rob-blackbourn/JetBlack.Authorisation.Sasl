using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using JetBlack.Authorisation.Utils;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms.CramMd5
{
    /// <summary>
    /// Implements "CRAM-MD5" authenticaiton. Defined in RFC 2195.
    /// </summary>
    public class CramMd5SaslServerMechanism : CramMd5SaslMechanism, ISaslServerMechanism
    {
        private bool _isCompleted;
        private bool _isAuthenticated;
        private readonly bool _requireSsl;
        private string _userName = "";
        private int _state = 0;
        private string _key = "";

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="requireSsl">Specifies if this mechanism is available to SSL connections only.</param>
        public CramMd5SaslServerMechanism(bool requireSsl)
        {
            _requireSsl = requireSsl;
        }

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public void Reset()
        {
            _isCompleted = false;
            _isAuthenticated = false;
            _userName = "";
            _state = 0;
            _key = "";
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientResponse</b> is null reference.</exception>
        /// <remarks>
        /// RFC 2195 2. Challenge-Response Authentication Mechanism.
        /// The authentication type associated with CRAM is "CRAM-MD5".
        ///
        /// The data encoded in the first ready response contains an
        /// presumptively arbitrary string of random digits, a timestamp, and the
        /// fully-qualified primary host name of the server.The syntax of the
        /// unencoded form must correspond to that of an RFC 822 'msg-id'
        /// [RFC822] as described in [POP3].
        /// 
        /// The client makes note of the data and then responds with a string
        /// consisting of the user name, a space, and a 'digest'.  The latter is
        /// computed by applying the keyed MD5 algorithm from[KEYED - MD5] where
        ///  the key is a shared secret and the digested text is the timestamp
        ///  (including angle-brackets).
        /// 
        /// This shared secret is a string known only to the client and server.
        /// The `digest' parameter itself is a 16-octet value which is sent in
        /// hexadecimal format, using lower-case ASCII characters.
        /// 
        /// When the server receives this client response, it verifies the digest
        /// provided.If the digest is correct, the server should consider the
        /// client authenticated and respond appropriately.
        /// 
        /// Example:
        ///     The examples in this document show the use of the CRAM mechanism with
        ///     the IMAP4 AUTHENTICATE command[IMAP - AUTH].  The base64 encoding of
        ///     the challenges and responses is part of the IMAP4 AUTHENTICATE
        ///     command, not part of the CRAM specification itself.
        /// 
        ///     S: * OK IMAP4 Server
        ///     C: A0001 AUTHENTICATE CRAM-MD5
        ///     S: + PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+
        ///     C: dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
        ///     S: A0001 OK CRAM authentication successful
        /// 
        ///    In this example, the shared secret is the string
        ///    'tanstaaftanstaaf'.  Hence, the Keyed MD5 digest is produced by
        ///    calculating
        /// 
        ///     MD5((tanstaaftanstaaf XOR opad),
        ///        MD5((tanstaaftanstaaf XOR ipad),
        ///        <1896.697170952@postoffice.reston.mci.net>))
        /// 
        ///    where ipad and opad are as defined in the keyed-MD5 Work in
        ///    Progress[KEYED - MD5] and the string shown in the challenge is the
        ///     base64 encoding of<1896.697170952@postoffice.reston.mci.net>. The
        ///     shared secret is null-padded to a length of 64 bytes.If the
        ///      shared secret is longer than 64 bytes, the MD5 digest of the
        ///      shared secret is used as a 16 byte input to the keyed MD5
        ///      calculation.
        /// 
        ///      This produces a digest value (in hexadecimal) of
        ///          b913a602c7eda7a495b4e6e7334d3890
        /// 
        ///    The user name is then prepended to it, forming
        ///       tim b913a602c7eda7a495b4e6e7334d3890
        ///     Which is then base64 encoded to meet the requirements of the IMAP4
        ///     AUTHENTICATE command(or the similar POP3 AUTH command), yielding
        ///    dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
        /// 
        /// </remarks>
        public byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            if (_state == 0)
            {
                ++_state;
                _key = "<" + Guid.NewGuid() + "@host" + ">";

                return Encoding.UTF8.GetBytes(_key);
            }
            else
            {
                // Parse client response. response = userName SP hash.
                var userHash = Encoding.UTF8.GetString(clientResponse).Split(' ');
                if (userHash.Length == 2 && !string.IsNullOrEmpty(userHash[0]))
                {
                    _userName = userHash[0];
                    var result = OnGetUserInfo(userHash[0]);
                    if (result.UserExists)
                    {
                        // hash = Hex(HmacMd5(hashKey,password))
                        var hash = NetUtils.ToHex(HmacMd5(_key, result.Password));
                        if (hash == userHash[1])
                        {
                            _isAuthenticated = true;
                        }
                    }
                }

                _isCompleted = true;
            }

            return null;
        }

        /// <summary>
        /// Calculates keyed md5 hash from specifieed text and with specified hash key.
        /// </summary>
        /// <param name="hashKey">MD5 key.</param>
        /// <param name="text">Text to hash.</param>
        /// <returns>Returns MD5 hash.</returns>
        private static byte[] HmacMd5(string hashKey, string text)
        {
            var kMd5 = new HMACMD5(Encoding.Default.GetBytes(text));
            return kMd5.ComputeHash(Encoding.ASCII.GetBytes(hashKey));
        }

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public bool IsCompleted
        {
            get { return _isCompleted; }
        }

        /// <summary>
        /// Gets if user has authenticated sucessfully.
        /// </summary>
        public bool IsAuthenticated
        {
            get { return _isAuthenticated; }
        }

        /// <summary>
        /// Gets if specified SASL mechanism is available only to SSL connection.
        /// </summary>
        public bool RequireSSL
        {
            get { return _requireSsl; }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public string UserName
        {
            get { return _userName; }
        }

        public Dictionary<string, object> Tags { get { return null; } }

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
            var retVal = new UserInfoEventArgs(userName);

            if (GetUserInfo != null)
                GetUserInfo(this, retVal);

            return retVal;
        }
    }
}
