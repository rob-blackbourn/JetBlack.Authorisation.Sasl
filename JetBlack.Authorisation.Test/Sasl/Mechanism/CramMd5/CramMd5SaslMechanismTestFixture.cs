using JetBlack.Authorisation.Sasl;
using JetBlack.Authorisation.Sasl.Mechanism.CramMd5;
using NUnit.Framework;

namespace JetBlack.Authorisation.Test.Sasl.Mechanism.CramMd5
{
    [TestFixture]
    public class CramMd5SaslMechanismTestFixture : SaslTextFixture
    {
        [Test]
        public void SmokeTest()
        {
            var client = new CramMd5SaslClientMechanism(Username, Password);
            var server = new CramMd5SaslServerMechanism(CheckUserInfo, Hostname);

            GenericTest(client, server);

            Assert.IsTrue(server.IsAuthenticated);
        }
    }
}
