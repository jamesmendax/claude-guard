using System;
using System.Security.Principal;
using ClaudeGuard.Processes;

public sealed class GuardFixtureAppContainer : IDisposable
{
    public string Name { get; private set; }
    public SecurityIdentifier Identity { get; private set; }

    public GuardFixtureAppContainer() : this(false) {}

    public GuardFixtureAppContainer(bool useDesktopName)
    {
        Name = (useDesktopName ? "claude-guard-" : "guard-fixture-") + Guid.NewGuid().ToString("N");
        Identity = GuardAppContainer.CreateProfile(Name);
    }

    public GuardContainedProcess Start(string executable, string arguments, bool lessPrivileged)
    {
        if (Identity == null) throw new ObjectDisposedException("GuardFixtureAppContainer");
        return GuardAppContainer.StartFixture(executable, arguments, Identity, lessPrivileged);
    }

    public void Dispose()
    {
        if (Identity == null) return;
        GuardAppContainer.RemoveProfile(Name);
        Identity = null;
    }
}
