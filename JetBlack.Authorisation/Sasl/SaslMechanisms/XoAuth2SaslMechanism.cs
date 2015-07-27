namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    public abstract class XoAuth2SaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "XOAUTH2"; }
        }
    }
}
