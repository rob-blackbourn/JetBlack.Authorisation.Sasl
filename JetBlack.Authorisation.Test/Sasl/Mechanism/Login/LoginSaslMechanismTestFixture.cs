using JetBlack.Authorisation.Sasl.Mechanism.Login;
using NUnit.Framework;

namespace JetBlack.Authorisation.Test.Sasl.Mechanism.Login
{
    [TestFixture]
    public class LoginSaslMechanismTestFixture : SaslTextFixture
    {
        [Test]
        public void SmokeTest()
        {
            var client = new LoginSaslClientMechanism(Username, Password);
            var server = new LoginSaslServerMechanism(Authorise);

            GenericTest(client, server);

            Assert.IsTrue(server.IsAuthenticated);
        }
    }
}
