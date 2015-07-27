namespace JetBlack.Authorisation.Sasl.SaslMechanisms.XoAuth2
{
    public abstract class XoAuth2SaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "XOAUTH2"; }
        }
    }
}
