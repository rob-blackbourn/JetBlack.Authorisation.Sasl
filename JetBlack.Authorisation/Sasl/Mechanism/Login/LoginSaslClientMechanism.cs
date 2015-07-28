using System;
using System.Text;

namespace JetBlack.Authorisation.Sasl.Mechanism.Login
{
    public class LoginSaslClientMechanism : LoginSaslMechanism, ISaslClientMechanism
    {
        private readonly string _password;
        private int _state;

        public LoginSaslClientMechanism(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Argument 'username' value must be specified.", "userName");
            if (password == null)
                throw new ArgumentNullException("password");

            UserName = userName;
            _password = password;
        }

        public byte[] Continue(byte[] serverResponse)
        {
            if (serverResponse == null)
                throw new ArgumentNullException("serverResponse");
            if (IsCompleted)
                throw new InvalidOperationException("Authentication is completed.");

            if (_state == 0)
            {
                ++_state;
                return Encoding.UTF8.GetBytes(UserName);
            }
            
            if (_state == 1)
            {
                ++_state;
                IsCompleted = true;
                return Encoding.UTF8.GetBytes(_password);
            }
            
            throw new InvalidOperationException("Authentication is completed.");
        }

        public bool IsCompleted { get; private set; }
        public string UserName { get; private set; }
        public bool SupportsInitialResponse { get { return false; } }
    }
}
