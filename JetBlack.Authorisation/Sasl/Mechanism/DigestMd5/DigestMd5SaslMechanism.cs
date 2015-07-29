namespace JetBlack.Authorisation.Sasl.Mechanism.DigestMd5
{
    public abstract class DigestMd5SaslMechanism : ISaslMechanism
    {
        /// <summary>
        /// Returns always "DIGEST-MD5".
        /// 
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
        /// </summary>
        public string Name
        {
            get { return "DIGEST-MD5"; }
        }
    }
}
