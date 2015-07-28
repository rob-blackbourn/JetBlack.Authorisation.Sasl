using JetBlack.Authorisation.Sasl.Mechanism.Plain;
using NUnit.Framework;

namespace JetBlack.Authorisation.Test.Sasl.Mechanism.Plain
{
    [TestFixture]
    public class PlanSaslMechanismTestFixture : SaslTextFixture
    {
        [Test]
        public void SmokeTest2()
        {
            var client = new PlainSaslClientMechanism(AuthorizationId, Username, Password);
            var server = new PlainSaslServerMechanism(Authorise);
            GenericTest(client, server);
            Assert.IsTrue(server.IsAuthenticated);
        }
    }
}
