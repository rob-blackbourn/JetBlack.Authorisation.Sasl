using JetBlack.Authorisation.Sasl;
using NUnit.Framework;

namespace JetBlack.Authorisation.Test.Sasl
{
    [TestFixture]
    public class SaslTextFixture
    {
        protected const string AuthorizationId = null;
        protected const string Username = "tim";
        protected const string Password = "tanstaaftanstaaf";
        protected const string Hostname = "postoffice.reston.mci.net";

        public void GenericTest(ISaslClientMechanism client, ISaslServerMechanism server)
        {
            var data = client.SupportsInitialResponse ? client.Continue(new byte[0]) : new byte[0];
            while (!(client.IsCompleted && server.IsCompleted))
            {
                data = server.Continue(data);
                if (data == null)
                    continue;
                data = client.Continue(data);
            }
        }

        public UserInfo CheckUserInfo(string userName)
        {
            if (userName != Username)
                return default(UserInfo);

            return new UserInfo(true, Username, Password);
        }

        public bool Authorise(string authenticationId, string username, string password)
        {
            return username == Username && password == Password;
        }
    }
}
