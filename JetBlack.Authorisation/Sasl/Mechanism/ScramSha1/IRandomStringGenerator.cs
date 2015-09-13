namespace JetBlack.Authorisation.Sasl.Mechanism.ScramSha1
{
    public interface IRandomStringGenerator
    {
        string Generate(int length, string legalCharacters);
    }
}
