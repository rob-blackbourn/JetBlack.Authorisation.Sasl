namespace JetBlack.Authorisation.Sasl
{
    public interface ISaslMechanism
    {
        /// <summary>
        /// Gets IANA-registered SASL authentication mechanism name.
        /// </summary>
        /// <remarks>The registered list is available from: http://www.iana.org/assignments/sasl-mechanisms .</remarks>
        string Name { get; }
    }
}
