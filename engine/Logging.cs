using System;
using System.Diagnostics;

namespace adeleg.engine
{
    public static class Log
    {
        private static TraceSource traceSource;

        public static void Initialize(bool consoleEnabled, string logFilePath)
        {
            if (!consoleEnabled && string.IsNullOrEmpty(logFilePath))
                return;

            traceSource = new TraceSource("adeleg", SourceLevels.Verbose);
            traceSource.Listeners.Clear();

            if (consoleEnabled)
            {
                var consoleListener = new ConsoleTraceListener(true);
                traceSource.Listeners.Add(consoleListener);
            }

            if (!string.IsNullOrEmpty(logFilePath))
            {
                var fileListener = new TextWriterTraceListener(logFilePath);
                traceSource.Listeners.Add(fileListener);
            }
        }

        public static void Verbose(string message)
        {
            if (traceSource == null) return;
            traceSource.TraceEvent(TraceEventType.Verbose, 0,
                DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff") + " [VERBOSE] " + message);
            traceSource.Flush();
        }

        public static void Info(string message)
        {
            if (traceSource == null) return;
            traceSource.TraceEvent(TraceEventType.Information, 0,
                DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff") + " [INFO] " + message);
            traceSource.Flush();
        }

        public static void Warn(string message)
        {
            if (traceSource == null) return;
            traceSource.TraceEvent(TraceEventType.Warning, 0,
                DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff") + " [WARN] " + message);
            traceSource.Flush();
        }

        public static void Error(string message)
        {
            if (traceSource == null) return;
            traceSource.TraceEvent(TraceEventType.Error, 0,
                DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff") + " [ERROR] " + message);
            traceSource.Flush();
        }

        public static void Close()
        {
            if (traceSource == null) return;
            traceSource.Flush();
            traceSource.Close();
            traceSource = null;
        }
    }
}
