using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace JetBlack.Authorisation
{
    /// <summary>
    /// This class implements Google Gmail OAUTH version 1.0.
    /// </summary>
    public class GmailOAuth1
    {
        private readonly Random _random = new Random();
        private readonly string _consumerKey;
        private readonly string _consumerSecret;
        private const string Scope = "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email";
        private string _requestToken;
        private string _requestTokenSecret;
        private string _accessToken;
        private string _accessTokenSecret;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public GmailOAuth1()
            : this("anonymous", "anonymous")
        {
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="consumerKey">OAuth consumer key.</param>
        /// <param name="consumerSecret">OAuth consumer secret.</param>
        /// <exception cref="ArgumentNullException">Is riased when <b>consumerKey</b> or <b>consumerSecret</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is riased when any of the arguments has invalid value.</exception>
        public GmailOAuth1(string consumerKey, string consumerSecret)
        {
            if (string.IsNullOrEmpty(consumerKey))
                throw new ArgumentException("Argument 'consumerKey' value must be specified.", "consumerKey");
            if (string.IsNullOrEmpty(consumerSecret))
                throw new ArgumentException("Argument 'consumerSecret' value must be specified.", "consumerSecret");

            _consumerKey = consumerKey;
            _consumerSecret = consumerSecret;
        }

        /// <summary>
        /// Gets Gmail request Token.
        /// </summary>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public void GetRequestToken()
        {
            GetRequestToken("oob");
        }

        /// <summary>
        /// Gets Gmail request Token.
        /// </summary>
        /// <param name="callback">OAuth callback Url.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>callback</b> is null reference.</exception>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public void GetRequestToken(string callback)
        {
            if (callback == null)
                throw new ArgumentNullException("callback");
            if (!string.IsNullOrEmpty(_requestToken))
                throw new InvalidOperationException("Invalid state, you have already called this 'GetRequestToken' method.");

            // For more info see: http://googlecodesamples.com/oauth_playground/

            var timestamp = GenerateTimeStamp();
            var nonce = GenerateNonce();

            var url = "https://www.google.com/accounts/OAuthGetRequestToken?scope=" + UrlEncode(Scope);
            const string sigUrl = "https://www.google.com/accounts/OAuthGetRequestToken";

            // Build signature base.
            var xxx = new StringBuilder();
            xxx.Append("oauth_callback=" + UrlEncode(callback));
            xxx.Append("&oauth_consumer_key=" + UrlEncode(_consumerKey));
            xxx.Append("&oauth_nonce=" + UrlEncode(nonce));
            xxx.Append("&oauth_signature_method=" + UrlEncode("HMAC-SHA1"));
            xxx.Append("&oauth_timestamp=" + UrlEncode(timestamp));
            xxx.Append("&oauth_version=" + UrlEncode("1.0"));
            xxx.Append("&scope=" + UrlEncode(Scope));
            var signatureBase = "GET" + "&" + UrlEncode(sigUrl) + "&" + UrlEncode(xxx.ToString());

            // Calculate signature.
            var signature = ComputeHmacSha1Signature(signatureBase, _consumerSecret, null);

            //Build Authorization header.
            var authHeader = new StringBuilder();
            authHeader.Append("Authorization: OAuth ");
            authHeader.Append("oauth_version=\"1.0\", ");
            authHeader.Append("oauth_nonce=\"" + nonce + "\", ");
            authHeader.Append("oauth_timestamp=\"" + timestamp + "\", ");
            authHeader.Append("oauth_consumer_key=\"" + _consumerKey + "\", ");
            authHeader.Append("oauth_callback=\"" + UrlEncode(callback) + "\", ");
            authHeader.Append("oauth_signature_method=\"HMAC-SHA1\", ");
            authHeader.Append("oauth_signature=\"" + UrlEncode(signature) + "\"");

            // Create web request and read response.
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Headers.Add(authHeader.ToString());
            using (var response = request.GetResponse())
            {
                using (var stream = response.GetResponseStream())
                {
                    if (stream == null)
                        throw new IOException("Failed to get a response.");
                    using (var reader = new StreamReader(stream))
                    {
                        var line = HttpUtility.UrlDecode(reader.ReadToEnd());
                        if (line == null)
                            throw new InvalidDataException("Unable to decode the input parameters.");
                        foreach (var parameter in line.Split('&'))
                        {
                            var nameValue = parameter.Split('=');
                            if (string.Equals(nameValue[0], "oauth_token", StringComparison.InvariantCultureIgnoreCase))
                                _requestToken = nameValue[1];
                            else if (string.Equals(nameValue[0], "oauth_token_secret", StringComparison.InvariantCultureIgnoreCase))
                                _requestTokenSecret = nameValue[1];
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Gets Gmail authorization Url.
        /// </summary>
        /// <returns>
        /// Returns Gmail authorization Url.
        /// </returns>
        public string GetAuthorizationUrl()
        {
            if (_requestToken == null)
            {
                throw new InvalidOperationException("You need call method 'GetRequestToken' before.");
            }

            return "https://accounts.google.com/OAuthAuthorizeToken?oauth_token=" + UrlEncode(_requestToken) + "&hd=default";
        }

        /// <summary>
        /// Gets Gmail access token.
        /// </summary>
        /// <param name="verificationCode">Google provided verfification code on authorization Url.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>verificationCode</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public void GetAccessToken(string verificationCode)
        {
            if (string.IsNullOrEmpty(verificationCode))
                throw new ArgumentException("Argument 'verificationCode' value must be specified.", "verificationCode");
            if (string.IsNullOrEmpty(_requestToken))
                throw new InvalidOperationException("Invalid state, you need to call 'GetRequestToken' method first.");
            if (!string.IsNullOrEmpty(_accessToken))
                throw new InvalidOperationException("Invalid state, you have already called this 'GetAccessToken' method.");

            // For more info see: http://googlecodesamples.com/oauth_playground/

            const string url = "https://www.google.com/accounts/OAuthGetAccessToken";
            var timestamp = GenerateTimeStamp();
            var nonce = GenerateNonce();

            // Build signature base.
            var xxx = new StringBuilder();
            xxx.Append("oauth_consumer_key=" + UrlEncode(_consumerKey));
            xxx.Append("&oauth_nonce=" + UrlEncode(nonce));
            xxx.Append("&oauth_signature_method=" + UrlEncode("HMAC-SHA1"));
            xxx.Append("&oauth_timestamp=" + UrlEncode(timestamp));
            xxx.Append("&oauth_token=" + UrlEncode(_requestToken));
            xxx.Append("&oauth_verifier=" + UrlEncode(verificationCode));
            xxx.Append("&oauth_version=" + UrlEncode("1.0"));
            var signatureBase = "GET" + "&" + UrlEncode(url) + "&" + UrlEncode(xxx.ToString());

            // Calculate signature.
            var signature = ComputeHmacSha1Signature(signatureBase, _consumerSecret, _requestTokenSecret);

            //Build Authorization header.
            var authHeader = new StringBuilder();
            authHeader.Append("Authorization: OAuth ");
            authHeader.Append("oauth_version=\"1.0\", ");
            authHeader.Append("oauth_nonce=\"" + nonce + "\", ");
            authHeader.Append("oauth_timestamp=\"" + timestamp + "\", ");
            authHeader.Append("oauth_consumer_key=\"" + _consumerKey + "\", ");
            authHeader.Append("oauth_verifier=\"" + UrlEncode(verificationCode) + "\", ");
            authHeader.Append("oauth_token=\"" + UrlEncode(_requestToken) + "\", ");
            authHeader.Append("oauth_signature_method=\"HMAC-SHA1\", ");
            authHeader.Append("oauth_signature=\"" + UrlEncode(signature) + "\"");

            // Create web request and read response.
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Headers.Add(authHeader.ToString());
            using (var response = request.GetResponse())
            {
                using (var stream = response.GetResponseStream())
                {
                    if (stream == null)
                        throw new IOException("Failed to get the response stream.");
                    using (var reader = new StreamReader(stream))
                    {
                        var line = HttpUtility.UrlDecode(reader.ReadToEnd());
                        if (line == null)
                            throw new InvalidDataException("Failed to decode the parameters");
                        foreach (var parameter in line.Split('&'))
                        {
                            var nameValue = parameter.Split('=');
                            if (string.Equals(nameValue[0], "oauth_token", StringComparison.InvariantCultureIgnoreCase))
                                _accessToken = nameValue[1];
                            else if (string.Equals(nameValue[0], "oauth_token_secret", StringComparison.InvariantCultureIgnoreCase))
                                _accessTokenSecret = nameValue[1];
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Gets Gmail XOAUTH authentication string.
        /// </summary>
        /// <returns>Returns Gmail XOAUTH authentication string.</returns>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public string GetXoAuthStringForSmtp()
        {
            return GetXoAuthStringForSmtp(Email ?? GetUserEmail());
        }

        /// <summary>
        /// Gets Gmail XOAUTH authentication string.
        /// </summary>
        /// <param name="email">Gmail email address.</param>
        /// <returns>Returns Gmail XOAUTH authentication string.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>email</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public string GetXoAuthStringForSmtp(string email)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("Argument 'email' value must be specified.", "email");
            if (string.IsNullOrEmpty(_accessToken))
                throw new InvalidOperationException("Invalid state, you need to call 'GetAccessToken' method first.");

            var url = "https://mail.google.com/mail/b/" + email + "/smtp/";
            var timestamp = GenerateTimeStamp();
            var nonce = GenerateNonce();

            // Build signature base.
            var xxx = new StringBuilder();
            xxx.Append("oauth_consumer_key=" + UrlEncode(_consumerKey));
            xxx.Append("&oauth_nonce=" + UrlEncode(nonce));
            xxx.Append("&oauth_signature_method=" + UrlEncode("HMAC-SHA1"));
            xxx.Append("&oauth_timestamp=" + UrlEncode(timestamp));
            xxx.Append("&oauth_token=" + UrlEncode(_accessToken));
            xxx.Append("&oauth_version=" + UrlEncode("1.0"));
            var signatureBase = "GET" + "&" + UrlEncode(url) + "&" + UrlEncode(xxx.ToString());

            // Calculate signature.
            var signature = ComputeHmacSha1Signature(signatureBase, _consumerSecret, _accessTokenSecret);

            var retVal = new StringBuilder();
            retVal.Append("GET ");
            retVal.Append(url);
            retVal.Append(" oauth_consumer_key=\"" + UrlEncode(_consumerKey) + "\"");
            retVal.Append(",oauth_nonce=\"" + UrlEncode(nonce) + "\"");
            retVal.Append(",oauth_signature=\"" + UrlEncode(signature) + "\"");
            retVal.Append(",oauth_signature_method=\"" + "HMAC-SHA1\"");
            retVal.Append(",oauth_timestamp=\"" + UrlEncode(timestamp) + "\"");
            retVal.Append(",oauth_token=\"" + UrlEncode(_accessToken) + "\"");
            retVal.Append(",oauth_version=\"" + "1.0\"");

            return retVal.ToString();
        }

        /// <summary>
        /// Gets Gmail XOAUTH authentication string.
        /// </summary>
        /// <returns>Returns Gmail XOAUTH authentication string.</returns>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public string GetXoAuthStringForImap()
        {
            return GetXoAuthStringForImap(Email ?? GetUserEmail());
        }

        /// <summary>
        /// Gets Gmail XOAUTH authentication string.
        /// </summary>
        /// <param name="email">Gmail email address.</param>
        /// <returns>Returns Gmail XOAUTH authentication string.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>email</b> is null reference.</exception>
        /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public string GetXoAuthStringForImap(string email)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("Argument 'email' value must be specified.", "email");
            if (string.IsNullOrEmpty(_accessToken))
                throw new InvalidOperationException("Invalid state, you need to call 'GetAccessToken' method first.");

            var url = "https://mail.google.com/mail/b/" + email + "/imap/";
            var timestamp = GenerateTimeStamp();
            var nonce = GenerateNonce();

            // Build signature base.
            var xxx = new StringBuilder();
            xxx.Append("oauth_consumer_key=" + UrlEncode(_consumerKey));
            xxx.Append("&oauth_nonce=" + UrlEncode(nonce));
            xxx.Append("&oauth_signature_method=" + UrlEncode("HMAC-SHA1"));
            xxx.Append("&oauth_timestamp=" + UrlEncode(timestamp));
            xxx.Append("&oauth_token=" + UrlEncode(_accessToken));
            xxx.Append("&oauth_version=" + UrlEncode("1.0"));
            var signatureBase = "GET" + "&" + UrlEncode(url) + "&" + UrlEncode(xxx.ToString());

            // Calculate signature.
            var signature = ComputeHmacSha1Signature(signatureBase, _consumerSecret, _accessTokenSecret);

            var retVal = new StringBuilder();
            retVal.Append("GET ");
            retVal.Append(url);
            retVal.Append(" oauth_consumer_key=\"" + UrlEncode(_consumerKey) + "\"");
            retVal.Append(",oauth_nonce=\"" + UrlEncode(nonce) + "\"");
            retVal.Append(",oauth_signature=\"" + UrlEncode(signature) + "\"");
            retVal.Append(",oauth_signature_method=\"" + "HMAC-SHA1\"");
            retVal.Append(",oauth_timestamp=\"" + UrlEncode(timestamp) + "\"");
            retVal.Append(",oauth_token=\"" + UrlEncode(_accessToken) + "\"");
            retVal.Append(",oauth_version=\"" + "1.0\"");

            return retVal.ToString();
        }

        /// <summary>
        /// Gets user Gmail email address. 
        /// </summary>
        /// <returns>Returns user Gmail email address.</returns>
        /// <exception cref="InvalidOperationException">Is raised when this method is called in invalid state.</exception>
        public string GetUserEmail()
        {
            if (string.IsNullOrEmpty(_accessToken))
            {
                throw new InvalidOperationException("Invalid state, you need to call 'GetAccessToken' method first.");
            }

            const string url = "https://www.googleapis.com/userinfo/email";
            var timestamp = GenerateTimeStamp();
            var nonce = GenerateNonce();

            // Build signature base.
            var xxx = new StringBuilder();
            xxx.Append("oauth_consumer_key=" + UrlEncode(_consumerKey));
            xxx.Append("&oauth_nonce=" + UrlEncode(nonce));
            xxx.Append("&oauth_signature_method=" + UrlEncode("HMAC-SHA1"));
            xxx.Append("&oauth_timestamp=" + UrlEncode(timestamp));
            xxx.Append("&oauth_token=" + UrlEncode(_accessToken));
            xxx.Append("&oauth_version=" + UrlEncode("1.0"));
            var signatureBase = "GET" + "&" + UrlEncode(url) + "&" + UrlEncode(xxx.ToString());

            // Calculate signature.
            var signature = ComputeHmacSha1Signature(signatureBase, _consumerSecret, _accessTokenSecret);

            //Build Authorization header.
            var authHeader = new StringBuilder();
            authHeader.Append("Authorization: OAuth ");
            authHeader.Append("oauth_version=\"1.0\", ");
            authHeader.Append("oauth_nonce=\"" + nonce + "\", ");
            authHeader.Append("oauth_timestamp=\"" + timestamp + "\", ");
            authHeader.Append("oauth_consumer_key=\"" + _consumerKey + "\", ");
            authHeader.Append("oauth_token=\"" + UrlEncode(_accessToken) + "\", ");
            authHeader.Append("oauth_signature_method=\"HMAC-SHA1\", ");
            authHeader.Append("oauth_signature=\"" + UrlEncode(signature) + "\"");

            // Create web request and read response.
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Headers.Add(authHeader.ToString());
            using (var response = request.GetResponse())
            {
                using (var stream = response.GetResponseStream())
                {
                    if (stream == null)
                        throw new IOException("Failed to get response stream");
                    using (var reader = new StreamReader(stream))
                    {
                        var line = HttpUtility.UrlDecode(reader.ReadToEnd());
                        if (line == null)
                            throw new InvalidDataException("Failed to decode input parameters.");
                        foreach (var parameter in line.Split('&'))
                        {
                            var nameValue = parameter.Split('=');
                            if (string.Equals(nameValue[0], "email", StringComparison.InvariantCultureIgnoreCase))
                            {
                                Email = nameValue[1];
                            }
                        }
                    }
                }
            }

            return Email;
        }

        private string UrlEncode(string value)
        {
            if (value == null)
                throw new ArgumentNullException("value");

            const string unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
            var retVal = new StringBuilder();

            foreach (var symbol in value)
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                    retVal.Append(symbol);
                else
                    retVal.Append('%' + String.Format("{0:X2}", (int)symbol));
            }

            return retVal.ToString();
        }

        private string ComputeHmacSha1Signature(string signatureBase, string consumerSecret, string tokenSecret)
        {
            if (signatureBase == null)
                throw new ArgumentNullException("signatureBase");
            if (consumerSecret == null)
                throw new ArgumentNullException("consumerSecret");

            var hmacsha1 = new HMACSHA1
            {
                Key = Encoding.ASCII.GetBytes(string.Format("{0}&{1}", UrlEncode(consumerSecret), string.IsNullOrEmpty(tokenSecret) ? "" : UrlEncode(tokenSecret)))
            };

            return Convert.ToBase64String(hmacsha1.ComputeHash(Encoding.ASCII.GetBytes(signatureBase)));
        }

        /// <summary>
        /// Creates the timestamp for the signature.        
        /// </summary>
        /// <returns></returns>
        private static string GenerateTimeStamp()
        {
            // Default implementation of UNIX time of the current UTC time
            var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);

            return Convert.ToInt64(ts.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Creates a nonce for the signature.
        /// </summary>
        /// <returns>The nonce</returns>
        private string GenerateNonce()
        {
            return _random.Next(123400, 9999999).ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Gets user Gmail email address. Returns null if no GetUserEmail method ever called.
        /// </summary>
        public string Email { get; private set; }
    }
}
