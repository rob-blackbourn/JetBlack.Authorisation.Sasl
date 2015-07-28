using JetBlack.Authorisation.Sasl.Mechanism.Plain;
using NUnit.Framework;

namespace JetBlack.Authorisation.Test.Sasl.Mechanism.Plain
{
    [TestFixture]
    public class PlanSaslMechanismTestFixture
    {
        [Test]
        public void SmokeTest()
        {
            var client = new PlainSaslClientMechanism("tim", "tanstaaftanstaaf");
            var server = new PlainSaslServerMechanism(false);

            var data = new byte[0];
            while (!client.IsCompleted && !server.IsCompleted)
            {
                data = client.Continue(data);
                data = server.Continue(data);
            }
        }
    }
}
