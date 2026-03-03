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
            {
                Close();
                return;
            }

            Close();

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
            string line = string.Format("{0} [VERBOSE] {1}", DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff"), message);
            foreach (TraceListener listener in traceSource.Listeners)
            {
                listener.WriteLine(line);
            }
        }

        public static void Info(string message)
        {
            if (traceSource == null) return;
            string line = string.Format("{0} [INFO] {1}", DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff"), message);
            foreach (TraceListener listener in traceSource.Listeners)
            {
                listener.WriteLine(line);
            }
        }

        public static void Warn(string message)
        {
            if (traceSource == null) return;
            string line = string.Format("{0} [WARN] {1}", DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff"), message);
            foreach (TraceListener listener in traceSource.Listeners)
            {
                listener.WriteLine(line);
                listener.Flush();
            }
        }

        public static void Error(string message)
        {
            if (traceSource == null) return;
            string line = string.Format("{0} [ERROR] {1}", DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff"), message);
            foreach (TraceListener listener in traceSource.Listeners)
            {
                listener.WriteLine(line);
                listener.Flush();
            }
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
