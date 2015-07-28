using System;
using System.Collections.Generic;

namespace JetBlack.Authorisation.Sasl
{
    /// <summary>
    /// This base class for server SASL authentication mechanisms.
    /// </summary>
    public interface ISaslServerMechanism : ISaslMechanism
    {
        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        void Reset();

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientRespone</b> is null reference.</exception>
        byte[] Continue(byte[] clientResponse);

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        bool IsCompleted { get; }

        /// <summary>
        /// Gets if user has authenticated sucessfully.
        /// </summary>
        bool IsAuthenticated { get; }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        string UserName { get; }

        /// <summary>
        /// Gets user data items collection.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Is raised when this object is disposed and this property is accessed.</exception>
        Dictionary<string, object> Tags { get; }
    }
}
