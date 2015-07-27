using System;

namespace JetBlack.Authorisation.Sasl
{
    /// <summary>
    /// This base class for client SASL authentication mechanisms. Defined in RFC 4422.
    /// </summary>
    public interface ISaslClientMechanism : ISaslMechanism
    {
        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="serverResponse">Server sent SASL response.</param>
        /// <returns>Returns challange request what must be sent to server or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>serverResponse</b> is null reference.</exception>
        byte[] Continue(byte[] serverResponse);

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        bool IsCompleted { get; }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        string UserName { get; }

        /// <summary>
        /// Gets if the authentication method supports SASL client "inital response".
        /// </summary>
        bool SupportsInitialResponse { get; }
    }
}
