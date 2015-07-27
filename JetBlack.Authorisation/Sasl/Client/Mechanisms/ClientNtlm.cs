using JetBlack.Authorisation.Utils;
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Client.Mechanisms
{
    /// <summary>
    /// Implements NTLM authentication.
    /// </summary>
    public class ClientNtlm : ClientMechanism
    {
        /// <summary>
        /// This class represents NTLM type 1 message.
        /// </summary>
        private class MessageType1
        {
            private readonly string _domain;
            private readonly string _host;

            /// <summary>
            /// Default constructor.
            /// </summary>
            /// <param name="domain">Domain name.</param>
            /// <param name="host">Host name.</param>
            /// <exception cref="ArgumentNullException">Is raised when <b>domain</b> or <b>host</b> is null reference.</exception>
            public MessageType1(string domain, string host)
            {
                if (domain == null)
                    throw new ArgumentNullException("domain");
                if (host == null)
                    throw new ArgumentNullException("host");

                _domain = domain;
                _host = host;
            }

            /// <summary>
            /// Converts this to binary NTML type 1 message.
            /// </summary>
            /// <returns>Returns this as binary NTML type 1 message.</returns>
            public byte[] ToByte()
            {
                /*
                struct {
                    byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
                    byte    type;            // 0x01
                    byte    zero[3];
                    short   flags;           // 0xb203
                    byte    zero[2];

                    short   dom_len;         // domain string length
                    short   dom_len;         // domain string length
                    short   dom_off;         // domain string offset
                    byte    zero[2];

                    short   host_len;        // host string length
                    short   host_len;        // host string length
                    short   host_off;        // host string offset (always 0x20)
                    byte    zero[2];

                    byte    host[*];         // host string (ASCII)
                    byte    dom[*];          // domain string (ASCII)
                } type-1-message
                         
                         0       1       2       3
                     +-------+-------+-------+-------+
                 0:  |  'N'  |  'T'  |  'L'  |  'M'  |
                     +-------+-------+-------+-------+
                 4:  |  'S'  |  'S'  |  'P'  |   0   |
                     +-------+-------+-------+-------+
                 8:  |   1   |   0   |   0   |   0   |
                     +-------+-------+-------+-------+
                12:  | 0x03  | 0xb2  |   0   |   0   |
                     +-------+-------+-------+-------+
                16:  | domain length | domain length |
                     +-------+-------+-------+-------+
                20:  | domain offset |   0   |   0   |
                     +-------+-------+-------+-------+
                24:  |  host length  |  host length  |
                     +-------+-------+-------+-------+
                28:  |  host offset  |   0   |   0   |
                     +-------+-------+-------+-------+
                32:  |  host string                  |
                     +                               +
                     .                               .
                     .                               .
                     +             +-----------------+
                     |             | domain string   |
                     +-------------+                 +
                     .                               .
                     .                               .
                     +-------+-------+-------+-------+

                */


                var domainLength = (short)_domain.Length;
                var hostLength = (short)_host.Length;

                var data = new byte[32 + domainLength + hostLength];

                data[0] = (byte)'N';
                data[1] = (byte)'T';
                data[2] = (byte)'L';
                data[3] = (byte)'M';
                data[4] = (byte)'S';
                data[5] = (byte)'S';
                data[6] = (byte)'P';
                data[7] = 0;
                data[8] = 1;
                data[9] = 0;
                data[10] = 0;
                data[11] = 0;

                data[12] = 0x03;
                data[13] = 0xb2;
                data[14] = 0;
                data[15] = 0;

                var domOff = (short)(32 + hostLength);

                data[16] = (byte)domainLength;
                data[17] = (byte)(domainLength >> 8);
                data[18] = data[16];
                data[19] = data[17];
                data[20] = (byte)domOff;
                data[21] = (byte)(domOff >> 8);

                data[24] = (byte)hostLength;
                data[25] = (byte)(hostLength >> 8);
                data[26] = data[24];
                data[27] = data[25];
                data[28] = 0x20;
                data[29] = 0x00;

                var host = Encoding.ASCII.GetBytes(_host.ToUpper(CultureInfo.InvariantCulture));
                Buffer.BlockCopy(host, 0, data, 32, host.Length);

                var domain = Encoding.ASCII.GetBytes(_domain.ToUpper(CultureInfo.InvariantCulture));
                Buffer.BlockCopy(domain, 0, data, domOff, domain.Length);

                return data;
            }
        }

        /// <summary>
        /// This class represents NTLM type 2 message.
        /// </summary>
        private class MessageType2
        {
            private readonly byte[] _nonce;

            /// <summary>
            /// Default constructor.
            /// </summary>
            /// <param name="nonce">NTLM 8 byte nonce.</param>
            /// <exception cref="ArgumentNullException">Is raised when <b>nonce</b> is null reference.</exception>
            /// <exception cref="ArgumentException">Is raised when any of the arguments has invalid value.</exception>
            private MessageType2(byte[] nonce)
            {
                if (nonce == null)
                    throw new ArgumentNullException("nonce");
                if (nonce.Length != 8)
                    throw new ArgumentException("Argument 'nonce' value must be 8 bytes value.", "nonce");

                _nonce = nonce;
            }

            /// <summary>
            /// Parses NTLM type 2 message.
            /// </summary>
            /// <param name="data">NTLM type 2 message.</param>
            /// <returns>Returns parsed NTLM type 2 message.</returns>
            /// <exception cref="ArgumentNullException">Is raised when <b>data</b> is null reference.</exception>
            public static MessageType2 Parse(byte[] data)
            {
                if (data == null)
                {
                    throw new ArgumentNullException("data");
                }

                /*
                struct {
                    byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
                    byte    type;            // 0x02
                    byte    zero[7];
                    short   msg_len;         // 0x28
                    byte    zero[2];
                    short   flags;           // 0x8201
                    byte    zero[2];

                    byte    nonce[8];        // nonce
                    byte    zero[8];
                } type-2-message
                
                             0       1       2       3
                         +-------+-------+-------+-------+
                     0:  |  'N'  |  'T'  |  'L'  |  'M'  |
                         +-------+-------+-------+-------+
                     4:  |  'S'  |  'S'  |  'P'  |   0   |
                         +-------+-------+-------+-------+
                     8:  |   2   |   0   |   0   |   0   |
                         +-------+-------+-------+-------+
                    12:  |   0   |   0   |   0   |   0   |
                         +-------+-------+-------+-------+
                    16:  |  message len  |   0   |   0   |
                         +-------+-------+-------+-------+
                    20:  | 0x01  | 0x82  |   0   |   0   |
                         +-------+-------+-------+-------+
                    24:  |                               |
                         +          server nonce         |
                    28:  |                               |
                         +-------+-------+-------+-------+
                    32:  |   0   |   0   |   0   |   0   |
                         +-------+-------+-------+-------+
                    36:  |   0   |   0   |   0   |   0   |
                         +-------+-------+-------+-------+
                */

                var nonce = new byte[8];
                Buffer.BlockCopy(data, 24, nonce, 0, 8);

                return new MessageType2(nonce);
            }

            /// <summary>
            /// Gets nonce.
            /// </summary>
            public byte[] Nonce
            {
                get { return _nonce; }
            }
        }

        /// <summary>
        /// This class represents NTLM type 3 message.
        /// </summary>
        private class MessageType3
        {
            private readonly string _domain;
            private readonly string _user;
            private readonly string _host;
            private readonly byte[] _lanManagerResponse;
            private readonly byte[] _ntResponse;

            /// <summary>
            /// Default constructor.
            /// </summary>
            /// <param name="domain">Domain name.</param>
            /// <param name="user">User name.</param>
            /// <param name="host">Host name.</param>
            /// <param name="lanManagerResponse">Lan Manager response.</param>
            /// <param name="ntResponse">NT response.</param>
            /// <exception cref="ArgumentNullException">Is raised when <b>domain</b>,<b>user</b>,<b>host</b>,<b>lm</b> or <b>nt</b> is null reference.</exception>
            public MessageType3(string domain, string user, string host, byte[] lanManagerResponse, byte[] ntResponse)
            {
                if (domain == null)
                    throw new ArgumentNullException("domain");
                if (user == null)
                    throw new ArgumentNullException("user");
                if (host == null)
                    throw new ArgumentNullException("host");
                if (lanManagerResponse == null)
                    throw new ArgumentNullException("lanManagerResponse");
                if (ntResponse == null)
                    throw new ArgumentNullException("ntResponse");

                _domain = domain;
                _user = user;
                _host = host;
                _lanManagerResponse = lanManagerResponse;
                _ntResponse = ntResponse;
            }

            /// <summary>
            /// Converts this to binary NTML type 3 message.
            /// </summary>
            /// <returns>Returns this as binary NTML type 3 message.</returns>
            public byte[] ToByte()
            {
                /*
                    struct {
                        byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
                        byte    type;            // 0x03
                        byte    zero[3];

                        short   lm_resp_len;     // LanManager response length (always 0x18)
                        short   lm_resp_len;     // LanManager response length (always 0x18)
                        short   lm_resp_off;     // LanManager response offset
                        byte    zero[2];

                        short   nt_resp_len;     // NT response length (always 0x18)
                        short   nt_resp_len;     // NT response length (always 0x18)
                        short   nt_resp_off;     // NT response offset
                        byte    zero[2];

                        short   dom_len;         // domain string length
                        short   dom_len;         // domain string length
                        short   dom_off;         // domain string offset (always 0x40)
                        byte    zero[2];

                        short   user_len;        // username string length
                        short   user_len;        // username string length
                        short   user_off;        // username string offset
                        byte    zero[2];

                        short   host_len;        // host string length
                        short   host_len;        // host string length
                        short   host_off;        // host string offset
                        byte    zero[6];

                        short   msg_len;         // message length
                        byte    zero[2];

                        short   flags;           // 0x8201
                        byte    zero[2];

                        byte    dom[*];          // domain string (unicode UTF-16LE)
                        byte    user[*];         // username string (unicode UTF-16LE)
                        byte    host[*];         // host string (unicode UTF-16LE)
                        byte    lm_resp[*];      // LanManager response
                        byte    nt_resp[*];      // NT response
                    } type-3-message
                                 0       1       2       3
                             +-------+-------+-------+-------+
                         0:  |  'N'  |  'T'  |  'L'  |  'M'  |
                             +-------+-------+-------+-------+
                         4:  |  'S'  |  'S'  |  'P'  |   0   |
                             +-------+-------+-------+-------+
                         8:  |   3   |   0   |   0   |   0   |
                             +-------+-------+-------+-------+
                        12:  |  LM-resp len  |  LM-Resp len  |
                             +-------+-------+-------+-------+
                        16:  |  LM-resp off  |   0   |   0   |
                             +-------+-------+-------+-------+
                        20:  |  NT-resp len  |  NT-Resp len  |
                             +-------+-------+-------+-------+
                        24:  |  NT-resp off  |   0   |   0   |
                             +-------+-------+-------+-------+
                        28:  | domain length | domain length |
                             +-------+-------+-------+-------+
                        32:  | domain offset |   0   |   0   |
                             +-------+-------+-------+-------+
                        36:  |  user length  |  user length  |
                             +-------+-------+-------+-------+
                        40:  |  user offset  |   0   |   0   |
                             +-------+-------+-------+-------+
                        44:  |  host length  |  host length  |
                             +-------+-------+-------+-------+
                        48:  |  host offset  |   0   |   0   |
                             +-------+-------+-------+-------+
                        52:  |   0   |   0   |   0   |   0   |
                             +-------+-------+-------+-------+
                        56:  |  message len  |   0   |   0   |
                             +-------+-------+-------+-------+
                        60:  | 0x01  | 0x82  |   0   |   0   |
                             +-------+-------+-------+-------+
                        64:  | domain string                 |
                             +                               +
                             .                               .
                             .                               .
                             +           +-------------------+
                             |           | user string       |
                             +-----------+                   +
                             .                               .
                             .                               .
                             +                 +-------------+
                             |                 | host string |
                             +-----------------+             +
                             .                               .
                             .                               .
                             +   +---------------------------+
                             |   | LanManager-response       |
                             +---+                           +
                             .                               .
                             .                               .
                             +            +------------------+
                             |            | NT-response      |
                             +------------+                  +
                             .                               .
                             .                               .
                             +-------+-------+-------+-------+
                */

                var domain = Encoding.Unicode.GetBytes(_domain.ToUpper(CultureInfo.InvariantCulture));
                var user = Encoding.Unicode.GetBytes(_user);
                var host = Encoding.Unicode.GetBytes(_host.ToUpper(CultureInfo.InvariantCulture));

                var data = new byte[64 + domain.Length + user.Length + host.Length + 24 + 24];

                data[0] = (byte)'N';
                data[1] = (byte)'T';
                data[2] = (byte)'L';
                data[3] = (byte)'M';
                data[4] = (byte)'S';
                data[5] = (byte)'S';
                data[6] = (byte)'P';
                data[7] = 0;
                data[8] = 3;
                data[9] = 0;
                data[10] = 0;
                data[11] = 0;

                // LM response 
                var lmresp_off = (short)(64 + domain.Length + user.Length + host.Length);
                data[12] = (byte)0x18;
                data[13] = (byte)0x00;
                data[14] = (byte)0x18;
                data[15] = (byte)0x00;
                data[16] = (byte)lmresp_off;
                data[17] = (byte)(lmresp_off >> 8);

                // NT response 
                short ntresp_off = (short)(lmresp_off + 24);
                data[20] = (byte)0x18;
                data[21] = (byte)0x00;
                data[22] = (byte)0x18;
                data[23] = (byte)0x00;
                data[24] = (byte)ntresp_off;
                data[25] = (byte)(ntresp_off >> 8);

                // domain 
                short dom_len = (short)domain.Length;
                short dom_off = 64;
                data[28] = (byte)dom_len;
                data[29] = (byte)(dom_len >> 8);
                data[30] = data[28];
                data[31] = data[29];
                data[32] = (byte)dom_off;
                data[33] = (byte)(dom_off >> 8);

                // username 
                short uname_len = (short)user.Length;
                short uname_off = (short)(dom_off + dom_len);
                data[36] = (byte)uname_len;
                data[37] = (byte)(uname_len >> 8);
                data[38] = data[36];
                data[39] = data[37];
                data[40] = (byte)uname_off;
                data[41] = (byte)(uname_off >> 8);

                // host 
                short host_len = (short)host.Length;
                short host_off = (short)(uname_off + uname_len);
                data[44] = (byte)host_len;
                data[45] = (byte)(host_len >> 8);
                data[46] = data[44];
                data[47] = data[45];
                data[48] = (byte)host_off;
                data[49] = (byte)(host_off >> 8);

                // message length 
                short msg_len = (short)data.Length;
                data[56] = (byte)msg_len;
                data[57] = (byte)(msg_len >> 8);

                // flags 
                data[60] = 0x01;
                data[61] = 0x82;
                data[62] = 0;
                data[63] = 0;

                Buffer.BlockCopy(domain, 0, data, dom_off, domain.Length);
                Buffer.BlockCopy(user, 0, data, uname_off, user.Length);
                Buffer.BlockCopy(host, 0, data, host_off, host.Length);
                Buffer.BlockCopy(_lanManagerResponse, 0, data, lmresp_off, 24);
                Buffer.BlockCopy(_ntResponse, 0, data, ntresp_off, 24);

                return data;
            }
        }

        #region class NTLM_Utils

        /// <summary>
        /// This class provides NTLM related utility methods.
        /// </summary>
        private class NTLM_Utils
        {
            #region static method CalculateLM

            /// <summary>
            /// Calculates NTLM NT response.
            /// </summary>
            /// <param name="nonce">Server nonce.</param>
            /// <param name="password">Password.</param>
            /// <returns>Returns NTLM NT response.</returns>
            /// <exception cref="ArgumentNullException">Is raised when <b>nonce</b> or <b>password</b> is null reference.</exception>
            public static byte[] CalculateLM(byte[] nonce, string password)
            {
                if (nonce == null)
                {
                    throw new ArgumentNullException("nonce");
                }
                if (password == null)
                {
                    throw new ArgumentNullException("password");
                }

                byte[] lmBuffer = new byte[21];
                byte[] magic = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
                byte[] nullEncMagic = { 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE };

                // create Lan Manager password 
                DES des = DES.Create();
                des.Mode = CipherMode.ECB;

                // Note: In .NET DES cannot accept a weak key 
                // this can happen for a null password 
                if (password.Length < 1)
                {
                    Buffer.BlockCopy(nullEncMagic, 0, lmBuffer, 0, 8);
                }
                else
                {
                    des.Key = PasswordToKey(password, 0);
                    des.CreateEncryptor().TransformBlock(magic, 0, 8, lmBuffer, 0);
                }

                // and if a password has less than 8 characters 
                if (password.Length < 8)
                {
                    Buffer.BlockCopy(nullEncMagic, 0, lmBuffer, 8, 8);
                }
                else
                {
                    des.Key = PasswordToKey(password, 7);
                    des.CreateEncryptor().TransformBlock(magic, 0, 8, lmBuffer, 8);
                }


                return calc_resp(nonce, lmBuffer);
            }

            #endregion

            #region static method CalculateNT

            /// <summary>
            /// Calculates NTLM LM response.
            /// </summary>
            /// <param name="nonce">Server nonce.</param>
            /// <param name="password">Password.</param>
            /// <returns>Returns NTLM LM response.</returns>
            /// <exception cref="ArgumentNullException">Is raised when <b>nonce</b> or <b>password</b> is null reference.</exception>
            public static byte[] CalculateNT(byte[] nonce, string password)
            {
                if (nonce == null)
                {
                    throw new ArgumentNullException("nonce");
                }
                if (password == null)
                {
                    throw new ArgumentNullException("password");
                }


                byte[] ntBuffer = new byte[21];
                _MD4 md4 = _MD4.Create();
                byte[] hash = md4.ComputeHash(Encoding.Unicode.GetBytes(password));
                Buffer.BlockCopy(hash, 0, ntBuffer, 0, 16);

                return calc_resp(nonce, ntBuffer);
            }

            #endregion


            #region static method calc_resp

            private static byte[] calc_resp(byte[] nonce, byte[] data)
            {
                /*
                 * takes a 21 byte array and treats it as 3 56-bit DES keys. The
                 * 8 byte nonce is encrypted with each key and the resulting 24
                 * bytes are stored in the results array.
                */

                byte[] response = new byte[24];
                DES des = DES.Create();
                des.Mode = CipherMode.ECB;

                des.Key = setup_des_key(data, 0);
                ICryptoTransform ct = des.CreateEncryptor();
                ct.TransformBlock(nonce, 0, 8, response, 0);

                des.Key = setup_des_key(data, 7);
                ct = des.CreateEncryptor();
                ct.TransformBlock(nonce, 0, 8, response, 8);

                des.Key = setup_des_key(data, 14);
                ct = des.CreateEncryptor();
                ct.TransformBlock(nonce, 0, 8, response, 16);

                return response;
            }

            #endregion

            #region static method setup_des_key

            private static byte[] setup_des_key(byte[] key56bits, int position)
            {
                byte[] key = new byte[8];
                key[0] = key56bits[position];
                key[1] = (byte)((key56bits[position] << 7) | (key56bits[position + 1] >> 1));
                key[2] = (byte)((key56bits[position + 1] << 6) | (key56bits[position + 2] >> 2));
                key[3] = (byte)((key56bits[position + 2] << 5) | (key56bits[position + 3] >> 3));
                key[4] = (byte)((key56bits[position + 3] << 4) | (key56bits[position + 4] >> 4));
                key[5] = (byte)((key56bits[position + 4] << 3) | (key56bits[position + 5] >> 5));
                key[6] = (byte)((key56bits[position + 5] << 2) | (key56bits[position + 6] >> 6));
                key[7] = (byte)(key56bits[position + 6] << 1);

                return key;
            }

            #endregion

            #region static method PasswordToKey

            private static byte[] PasswordToKey(string password, int position)
            {
                byte[] key7 = new byte[7];
                int len = System.Math.Min(password.Length - position, 7);
                Encoding.ASCII.GetBytes(password.ToUpper(CultureInfo.CurrentCulture), position, len, key7, 0);
                byte[] key8 = setup_des_key(key7, 0);

                return key8;
            }

            #endregion
        }

        #endregion

        private readonly string _domain;
        private readonly string _userName;
        private readonly string _password;

        private bool _isCompleted;
        private int _state;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="domain">Domain name.</param>
        /// <param name="userName">User login name.</param>
        /// <param name="password">Password.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>domain</b>,<b>userName</b> or <b>passowrd</b> is null reference.</exception>
        public ClientNtlm(string domain, string userName, string password)
        {
            _userName = null;
            if (domain == null)
            {
                throw new ArgumentNullException("domain");
            }
            if (userName == null)
            {
                throw new ArgumentNullException("userName");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            _domain = domain;
            _userName = userName;
            _password = password;
        }


        #region method Continue

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="serverResponse">Server sent SASL response.</param>
        /// <returns>Returns challange request what must be sent to server or null if authentication has completed.</returns>
        /// <exception cref="InvalidOperationException">Is raised when this method is called when authentication is completed.</exception>
        public override byte[] Continue(byte[] serverResponse)
        {
            if (_isCompleted)
            {
                throw new InvalidOperationException("Authentication is completed.");
            }

            /*             
                Example:
                    C : AUTH NTLM 
                    S : 334 OK 
                    C : TlRMTVNTUAABAAAAB7I .... rest of client intro (message type 1) 
                    S : 334 TlRMTVNTUAABAAAAA4I .... rest of server challenge (message type 2) 
                    C : TlRMTVNTUAADAAAAGAA .... rest of client response (message type 3) 
                    S : 235 AUTH OK 
            */

            if (_state == 0)
            {
                _state++;

                return new MessageType1(_domain, Environment.MachineName).ToByte();
            }
            else if (_state == 1)
            {
                _state++;
                _isCompleted = true;

                byte[] nonce = MessageType2.Parse(serverResponse).Nonce;

                return new MessageType3(
                    _domain,
                    _userName,
                    Environment.MachineName,
                    NTLM_Utils.CalculateLM(nonce, _password),
                    NTLM_Utils.CalculateNT(nonce, _password)
                ).ToByte();
            }
            else
            {
                throw new InvalidOperationException("Authentication is completed.");
            }
        }

        #endregion


        #region Properties implementation

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public override bool IsCompleted
        {
            get { return _isCompleted; }
        }

        /// <summary>
        /// Returns always "NTLM".
        /// </summary>
        public override string Name
        {
            get { return "NTLM"; }
        }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public override string UserName
        {
            get { return _userName; }
        }

        /// <summary>
        /// Gets if the authentication method supports SASL client "inital response".
        /// </summary>
        public override bool SupportsInitialResponse
        {
            get { return true; }
        }

        #endregion
    }
}
