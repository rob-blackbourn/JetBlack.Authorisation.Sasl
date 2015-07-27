using System.Timers;

namespace JetBlack.Authorisation.Utils
{
    //
    // Summary:
    //     Represents the method that will handle the System.Timers.Timer.Elapsed event
    //     of a System.Timers.Timer.
    //
    // Parameters:
    //   sender:
    //     The source of the event.
    //
    //   e:
    //     An System.Timers.ElapsedEventArgs object that contains the event data.
    public delegate void ElapsedEventHandler(object sender, ElapsedEventArgs e);
}
