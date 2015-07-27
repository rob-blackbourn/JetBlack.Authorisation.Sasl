namespace JetBlack.Authorisation.Sasl
{
    public abstract class SaslMechanism
    {
        /// <summary>
        /// Gets IANA-registered SASL authentication mechanism name.
        /// </summary>
        /// <remarks>The registered list is available from: http://www.iana.org/assignments/sasl-mechanisms .</remarks>
        public abstract string Name { get; }
    }
}
