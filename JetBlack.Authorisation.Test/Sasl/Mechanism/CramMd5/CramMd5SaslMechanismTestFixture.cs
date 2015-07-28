using JetBlack.Authorisation.Sasl;
using JetBlack.Authorisation.Sasl.Mechanism.CramMd5;
using NUnit.Framework;

namespace JetBlack.Authorisation.Test.Sasl.Mechanism.CramMd5
{
    [TestFixture]
    public class CramMd5SaslMechanismTestFixture
    {
        [Test]
        public void SmokeTest()
        {
            const string username = "tim";
            const string password = "tanstaaftanstaaf";
            const string hostname = "postoffice.reston.mci.net";
            var client = new CramMd5SaslClientMechanism(username, password);
            var server = new CramMd5SaslServerMechanism(u => new UserInfo(u == username, username, u == username ? password : null), hostname);

            var data = new byte[0];
            while (!(client.IsCompleted && server.IsCompleted))
            {
                data = server.Continue(data);
                if (data != null)
                    data = client.Continue(data);
            }

            Assert.IsTrue(server.IsAuthenticated);
        }
    }
}
