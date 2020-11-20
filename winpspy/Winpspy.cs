using System;
using System.Linq;
using System.IO;
using System.Security.Permissions;
using System.Threading;
using System.Collections.Generic;
using System.Diagnostics;
using System.Timers;
using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace winpspy
{
    class Winpspy
    {
        static Dictionary<int, Process> activeProcesses = new Dictionary<int, Process>();
        static List<String> activePipes = new List<String>();
        static StreamWriter logWriter;
        static readonly string[] Blacklist = { "AutomaticDestinations" };
        static readonly string[] Keywords = { "exampleKeyword" };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);


        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA
           lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FindClose(IntPtr hFindFile);


        [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
        static void Main(string[] args)
        {

            Console.WriteLine("Winpspy - by xct");

            if (args.Length < 1)
            {                
               Console.WriteLine("Usage: watcher.exe <path to monitor>");
               return;
            }

            // Monitor Processes, Pipes
            var procTimer = new System.Timers.Timer(1000);
            procTimer.Enabled = true;
            procTimer.Elapsed += new ElapsedEventHandler(ProcDump);
            procTimer.Elapsed += new ElapsedEventHandler(PipeDump);
            procTimer.Start();

            // Monitor File Changes
            string logPath = Directory.GetCurrentDirectory() + @"\watcher.log";
            logWriter = new StreamWriter(logPath);

            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = args[0];

                watcher.IncludeSubdirectories = true;
                watcher.NotifyFilter = NotifyFilters.Attributes |
                NotifyFilters.CreationTime |
                NotifyFilters.DirectoryName |
                NotifyFilters.FileName |
                NotifyFilters.LastAccess |
                NotifyFilters.LastWrite |
                NotifyFilters.Security |
                NotifyFilters.Size;

                watcher.Changed += new FileSystemEventHandler(OnChanged);
                watcher.Created += new FileSystemEventHandler(OnChanged);
                watcher.Deleted += new FileSystemEventHandler(OnChanged);
                watcher.Renamed += new RenamedEventHandler(OnRenamed);
                watcher.EnableRaisingEvents = true;
                Console.WriteLine("Press \'q\' to quit.");
                Console.WriteLine();
                while (Console.Read() != 'q') ;
                logWriter.Close();
            }
            catch (IOException e)
            {
                Console.WriteLine("A Exception Occurred :" + e);
            }
            catch (Exception oe)
            {
                Console.WriteLine("An Exception Occurred :" + oe);
            }

        }

        static void Log(string text)
        {
            Console.WriteLine(text);
            logWriter.WriteLine(text);
            logWriter.Flush();
        }

        static void OnChanged(object source, FileSystemEventArgs e)
        {
            var canRead = false;
            var canWrite = false;


            if (!Blacklist.Any(e.FullPath.Contains))
            {
                try
                {
                    using (var fs = File.Open(e.FullPath, FileMode.Open))
                    {
                        canRead = fs.CanRead;
                        canWrite = fs.CanWrite;
                        if (canRead)
                        {
                            Log(String.Format("[*] File: {0} {1} [Read]", e.FullPath, e.ChangeType));
                            if (canWrite)
                            {
                                Log(String.Format("[*] File: {0} {1} [Read/Write]", e.FullPath, e.ChangeType));
                            }
                        }
                    }
                }
                catch
                {
                    Log(String.Format("[*] File: {0} {1} [No Access/Locked]", e.FullPath, e.ChangeType));
                }

                // check files for keywords
                new Thread(() =>
                {
                    try
                    {
                        Thread.CurrentThread.IsBackground = true;
                        var stream = WaitForFile(e.FullPath, FileMode.Open, FileAccess.Read, FileShare.None);
                        string contents;
                        using (var sr = new StreamReader(stream))
                        {
                            contents = sr.ReadToEnd();
                            foreach (string k in Keywords)
                            {
                                if (contents.IndexOf(k) > -1)
                                    Log(contents);

                            }
                        }
                    }
                    catch
                    {
                        // ignore
                    }
                }).Start();
            }
        }
        static void OnRenamed(object source, RenamedEventArgs e)
        {
            var canRead = false;
            var canWrite = false;
            if (!Blacklist.Any(e.FullPath.Contains))
            {
                try
                {
                    using (var fs = File.Open(e.FullPath, FileMode.Open))
                    {
                        canRead = fs.CanRead;
                        canWrite = fs.CanWrite;
                        if (canRead)
                        {
                            Log(String.Format("[*] File: {0} to {1} Renamed [Read]", e.OldFullPath, e.FullPath));
                            if (canWrite)
                            {
                                Log(String.Format("[*] File: {0} to {1} Renamed [Read/Write]", e.OldFullPath, e.FullPath));
                            }
                        }
                    }
                }
                catch
                {
                    Log(String.Format("[*] File: {0} to {1} Renamed [No Access/Locked]", e.OldFullPath, e.FullPath));
                }
            }
        }
        static FileStream WaitForFile(string fullPath, FileMode mode, FileAccess access, FileShare share)
        {
            for (int numTries = 0; numTries < 10; numTries++)
            {
                FileStream fs = null;
                try
                {
                    fs = new FileStream(fullPath, mode, access, share);
                    return fs;
                }
                catch (IOException)
                {
                    if (fs != null)
                    {
                        fs.Dispose();
                    }
                    Thread.Sleep(50);
                }
            }
            return null;
        }


        static void ProcDump(object sender, ElapsedEventArgs e)
        {
            Dictionary<int, Process> currentProcesses = new Dictionary<int, Process>();
            foreach (Process p in Process.GetProcesses())
            {
                currentProcesses[p.Id] = p;
            }
            var activeKeys = activeProcesses.Keys.ToList();
            var currentKeys = currentProcesses.Keys.ToList();
            var closedProceses = activeKeys.Except(currentKeys);

            foreach (int i in closedProceses)
            {
                Log("[-] Process: " + activeProcesses[i]);
                activeProcesses.Remove(i);
            }

            foreach (Process p in currentProcesses.Values)
            {
                if (!activeProcesses.ContainsKey(p.Id))
                {
                    // new process
                    activeProcesses[p.Id] = p;
                    var args = ProcessCommandLine.Retrieve(p, out var cl);
                    var cmdLineArray = ProcessCommandLine.CommandLineToArgs(cl);
                    var cmdString = string.Join(",", cmdLineArray.Select(x => x));
                    Log("[+] Process: " + p.ProcessName + " (ID: " + p.Id + ", Args: [" + cmdString + "])");
                }
                else
                {
                    // known process
                }
            }
        }


        static void PipeDump(object sender, ElapsedEventArgs e)
        {
            var namedPipes = new List<string>();
            WIN32_FIND_DATA lpFindFileData;

            var ptr = FindFirstFile(@"\\.\pipe\*", out lpFindFileData);
            namedPipes.Add(lpFindFileData.cFileName);
            while (FindNextFile(ptr, out lpFindFileData))
            {
                namedPipes.Add(lpFindFileData.cFileName);
            }
            FindClose(ptr);

            foreach (var p in namedPipes)
            {
                // new pipe
                if (!activePipes.Contains(p))
                {
                    Log("[+] Pipe: " + p);
                }
            }
            foreach (var p in activePipes)
            {
                // new pipe
                if (!namedPipes.Contains(p))
                {
                    Log("[-] Pipe: " + p);
                }
            }
            activePipes = namedPipes;
        }
    }
}
