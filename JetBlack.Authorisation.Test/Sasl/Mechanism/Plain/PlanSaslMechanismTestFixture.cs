using JetBlack.Authorisation.Sasl.Mechanism.Plain;
using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace JetBlack.Authorisation.Test.Sasl.Mechanism.Plain
{
    [TestFixture]
    public class PlanSaslMechanismTestFixture
    {
        [Test]
        public void SmokeTest()
        {
            const string username = "tim";
            const string password = "tanstaaftanstaaf";
            var client = new PlainSaslClientMechanism(null, username, password);
            var server = new PlainSaslServerMechanism((_authorizationId, _username, _password) => _username == username && _password == password && _authorizationId == null);

            var data = new byte[0];
            while (!client.IsCompleted && !server.IsCompleted)
            {
                data = client.Continue(data);
                data = server.Continue(data);
            }
        }
    }
}
