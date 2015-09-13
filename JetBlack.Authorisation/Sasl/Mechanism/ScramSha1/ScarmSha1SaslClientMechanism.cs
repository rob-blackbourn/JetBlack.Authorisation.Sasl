using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JetBlack.Authorisation.Sasl.Mechanism.ScramSha1
{
    public class ScarmSha1SaslClientMechanism : ScramSha1SaslMechanism, ISaslClientMechanism
    {
        private readonly string _password;
        private int _state;

        public ScarmSha1SaslClientMechanism(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Value must be specified.", "userName");
            if (password == null)
                throw new ArgumentNullException("password"); 
            
            IsCompleted = false;
            _password = password;
            UserName = userName;
        }

        public byte[] Continue(byte[] serverResponse)
        {
        }

        public bool IsCompleted { get; private set; }
        public string UserName { get; private set; }
        public bool SupportsInitialResponse { get { return true; } }
    }
}
