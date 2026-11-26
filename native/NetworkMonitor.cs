using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace ClaudeGuardNative
{
    /// <summary>
    /// Event-driven Windows IP Helper watcher using NotifyRouteChange2 and NotifyIpInterfaceChange.
    /// Wakes session verification immediately when any route or IP interface state changes,
    /// avoiding unnecessary delay while falling back cleanly to timed polling if registration fails.
    /// </summary>
    public sealed class NetworkChangeWatcher : IDisposable
    {
        private const ushort AddressFamilyUnspec = 0;
        private const uint NoError = 0;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void RouteChangeCallback(IntPtr callerContext, IntPtr row, int notificationType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void InterfaceChangeCallback(IntPtr callerContext, IntPtr row, int notificationType);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern uint NotifyRouteChange2(
            ushort family,
            RouteChangeCallback callback,
            IntPtr callerContext,
            [MarshalAs(UnmanagedType.U1)] bool initialNotification,
            out IntPtr notificationHandle);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern uint NotifyIpInterfaceChange(
            ushort family,
            InterfaceChangeCallback callback,
            IntPtr callerContext,
            [MarshalAs(UnmanagedType.U1)] bool initialNotification,
            out IntPtr notificationHandle);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern uint CancelMibChangeNotify2(IntPtr notificationHandle);

        private readonly AutoResetEvent signal = new AutoResetEvent(false);
        private readonly RouteChangeCallback routeDelegate;
        private readonly InterfaceChangeCallback interfaceDelegate;
        private IntPtr routeHandle = IntPtr.Zero;
        private IntPtr interfaceHandle = IntPtr.Zero;
        private long eventCount;
        private int disposed;

        public bool IsActive
        {
            get { return routeHandle != IntPtr.Zero || interfaceHandle != IntPtr.Zero; }
        }

        public long EventCount
        {
            get { return Interlocked.Read(ref eventCount); }
        }

        public NetworkChangeWatcher()
            : this(true)
        {
        }

        public NetworkChangeWatcher(bool registerNativeCallbacks)
        {
            routeDelegate = OnRouteChanged;
            interfaceDelegate = OnInterfaceChanged;

            if (!registerNativeCallbacks)
                return;

            try
            {
                IntPtr rh;
                if (NotifyRouteChange2(AddressFamilyUnspec, routeDelegate, IntPtr.Zero, false, out rh) == NoError)
                    routeHandle = rh;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }

            try
            {
                IntPtr ih;
                if (NotifyIpInterfaceChange(AddressFamilyUnspec, interfaceDelegate, IntPtr.Zero, false, out ih) == NoError)
                    interfaceHandle = ih;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        private void OnRouteChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            SignalChange();
        }

        private void OnInterfaceChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            SignalChange();
        }

        public void TriggerForTest()
        {
            SignalChange();
        }

        public void ScheduleTriggerForTest(int delayMs)
        {
            if (delayMs < 0)
                delayMs = 0;
            ThreadPool.QueueUserWorkItem(delegate
            {
                if (delayMs > 0)
                    Thread.Sleep(delayMs);
                SignalChange();
            });
        }

        private void SignalChange()
        {
            if (Thread.VolatileRead(ref disposed) != 0)
                return;
            Interlocked.Increment(ref eventCount);
            try { signal.Set(); }
            catch (ObjectDisposedException) { }
        }

        /// <summary>
        /// Waits up to timeoutMs milliseconds. Returns true if woken early by a route/interface event.
        /// </summary>
        public bool Wait(int timeoutMs)
        {
            if (Thread.VolatileRead(ref disposed) != 0)
                return false;
            if (timeoutMs < 0)
                timeoutMs = 0;
            try { return signal.WaitOne(timeoutMs); }
            catch (ObjectDisposedException) { return false; }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;

            IntPtr rh = Interlocked.Exchange(ref routeHandle, IntPtr.Zero);
            if (rh != IntPtr.Zero)
            {
                try { CancelMibChangeNotify2(rh); }
                catch (DllNotFoundException) { }
                catch (EntryPointNotFoundException) { }
            }

            IntPtr ih = Interlocked.Exchange(ref interfaceHandle, IntPtr.Zero);
            if (ih != IntPtr.Zero)
            {
                try { CancelMibChangeNotify2(ih); }
                catch (DllNotFoundException) { }
                catch (EntryPointNotFoundException) { }
            }

            signal.Dispose();
        }
    }
}
