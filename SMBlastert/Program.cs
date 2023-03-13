using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SMBLibrary;
using SMBLibrary.Client;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Diagnostics;
using System.Text.RegularExpressions;



namespace SMBlaster
{
    internal class Program
    {
        static void printBanner()
        {
            Console.WriteLine(@"
                          ▄▄▄▄
███████▄▄▄▄▄▄▄▐█▌▄▄▄▄▐█▌▄▄████▄▄▄▄▄▄▄▄▄▄▄                                                                                                             
██████████████▐█▌████▐█▌█████████████████  
▀▀▀▀▀▀▀       ▐█▌    ▐█▌                                                                           
        ▄▄▄▄▄▄▐█▌▄▄▄▄▐█▌▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀▀▀▀▄▄▄▄▄█████                                                                                                  
         ██████████████████████████████▀▀▀▀▀▀██████████                                                                                                  
        ▄██████████████████▀▀▀▀▌       ▀▀▀▀▀▀     ▀▀▀▀▀                                                                                                  
        ██████████████████▀▀▀▀▀▌                                                                                                                      
         ███████▌l   ████▀▀▀▀▀▀▌           
       ▄█████▌  ▌▄▄▄▄██████████     ▐████████████▄     ▄█████████████████▄ ████▌         ▐███████     ████████▌███████████▌███████████ ████████████▄  
      ▄▄▄████                      ▐█████▀▀▀▀▐█████▄ ▄██████▐████    █████ ████▌         ████ ███▌   █████▀▀▀▀▀▀▀▀█████▀▀▀▀████▀▀▀▀▀▀▀ █████    ████  
     ▄▄▄████▌                       ▀█████▄  ▐█████████████▌▐███████████▀  ████▌        ████   ███▄   █████▄      █████    █████████   █████▄▄▄████▀  
     ▄▄█████                          ▀█████ ▐███ █████ ███▌▐████▀▀▀▀▀████ ████▌       █████▄▄▄████    ▀█████▄    █████    ████▀▀▀▀▀   ██████████     
     ▀█████▀                  ██████████████▌▐███  ███  ███▌▐████▄▄▄▄▄████▌██████████▌█████▀▀▀▀████▌██████████    █████    ███████████▌█████ ▀███████ 
       ▀▀▀                    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀   ▀   ▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀     ▀▀▀▀▀▀▀▀▀▀▀▀▀     ▀▀▀▀▀    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀   ▀▀▀▀▀▀ 
");
        }

        // Create a lock object to synchronize access to the file
        private static object fileLock = new object();

        //This is a simply TCP ACK implementation on port 445, with a 1500 miliseconds timeout so it doesn't hang
        static async Task<bool> IsMachineAccessible(string ipAddress)
        {
            try
            {
                using (TcpClient tcpClient = new TcpClient())
                {
                    Task connectTask = tcpClient.ConnectAsync(ipAddress, 445);
                    if (await Task.WhenAny(connectTask, Task.Delay(1500)) == connectTask && tcpClient.Connected)
                    {
                        NetworkStream stream = tcpClient.GetStream();
                        byte[] packet = new byte[] { 0x00 };
                        stream.Write(packet, 0, 1);
                        tcpClient.Close();
                        return true;
                    }
                    else
                    {
                        tcpClient.Close();
                        return false;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        static void Main(string[] args)
        {
            printBanner();

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            CommandLineParser.ParsedParameters parsedParameters = new CommandLineParser().parseParameters(args);
            RuleParser.Pinto parsedRules = new RuleParser().parseRulesFile(parsedParameters.rules);

            //preprocessing parsedRules to create ruleFilter, a filter used further down so SMBLaster doesn't request file's permissions that are not used by any rules.
            RuleParser.RuleFilter ruleFilter = new RuleParser.RuleFilter();
            foreach (RuleParser.Rule rule in parsedRules.Rules)
            {
                if (rule.Writable != null)
                {
                    ruleFilter.Writable = true;
                }
                if (rule.Readable != null)
                {
                    ruleFilter.Readable = true;
                }
                if (rule.Deletable != null)
                {
                    ruleFilter.Deletable = true;
                }
                if (rule.DirectoryWritable != null)
                {
                    ruleFilter.DirectoryWritable = true;
                }
                if (rule.Filename != null)
                {
                    ruleFilter.Filename = true;
                }
                if (rule.Path != null)
                {
                    ruleFilter.Path = true;
                }
                if (rule.Extension != null)
                {
                    ruleFilter.Extension = true;
                }
                if (rule.Content != null)
                {
                    ruleFilter.Content = true;
                }
                if (rule.Seizable != null)
                {
                    ruleFilter.Seizable = true;
                }
            }

            //This is how many concurrent threads SMBLaster will spawn, where each thread deals with a single target machine and all of it's shares/files.
            var options = new ParallelOptions()
            {
                MaxDegreeOfParallelism = 15
            };

            Console.WriteLine($"[*] Starting {(char.ToUpper(parsedParameters.method[0]) + parsedParameters.method.Substring(1))} scan on {parsedParameters.target.Count} targets.");

            Parallel.ForEach(parsedParameters.target, options, targetMachine =>
            {
                try
                {
                    if (IsMachineAccessible(targetMachine).Result)
                    {
                        SMB2Client client = new SMB2Client();
                        if (client.Connect(IPAddress.Parse(targetMachine), SMBTransportType.DirectTCPTransport))
                        {
                            NTStatus status = client.Login(parsedParameters.domain, parsedParameters.username, parsedParameters.password);
                            if (status == NTStatus.STATUS_SUCCESS)
                            {
                                List<string> shares = client.ListShares(out status);

                                foreach (string name in shares)
                                {
                                    ISMBFileStore fileStore = client.TreeConnect(name, out status);

                                    if (status == NTStatus.STATUS_SUCCESS)
                                    {
                                        //defining if we have READ access to the root directory of the share
                                        object readDirectoryHandle;
                                        FileStatus readFileStatus;
                                        NTStatus readStatus = fileStore.CreateFile(out readDirectoryHandle, out readFileStatus, String.Empty, AccessMask.GENERIC_READ, SMBLibrary.FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);

                                        if (readStatus == NTStatus.STATUS_SUCCESS)
                                        {
                                            //defining if we have WRITE access to the root directory of the share, implying we have write access to the share
                                            object writeDirectoryHandle;
                                            FileStatus writeFileStatus;
                                            NTStatus writeStatus = fileStore.CreateFile(out writeDirectoryHandle, out writeFileStatus, String.Empty, AccessMask.GENERIC_WRITE, SMBLibrary.FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);

                                            if (writeStatus == NTStatus.STATUS_SUCCESS)
                                            {
                                                Console.WriteLine($"[+] Found share: \"\\\\{targetMachine}\\{name}\" with [WRITE].");
                                                fileStore.CloseFile(writeDirectoryHandle);
                                            }
                                            else
                                            {
                                                Console.WriteLine($"[+] Found share: \"\\\\{targetMachine}\\{name}\" with [READ].");
                                            }
                                            fileStore.CloseFile(readDirectoryHandle);
                                        }
                                        else
                                        {
                                            Console.WriteLine($"[+] Found share: \"\\\\{targetMachine}\\{name}\" with [NO ACCESS].");
                                        }

                                        //if method parameter received "simple", skip file discovery and rule matching.
                                        if (parsedParameters.method == "simple")
                                        {
                                            continue;
                                        }

                                        //prepares the variables and starts the recursive loop to find every file and directory contained on the share
                                        List<string> sharedDirectories = new List<string>() { String.Empty };
                                        List<string> sharedFiles = new List<string>();
                                        object directoryHandle;
                                        FileStatus fileStatus;

                                        int length = sharedDirectories.Count;
                                        for (int i = 0; i < length; i++)
                                        {
                                            string tempDirectory = sharedDirectories[i];
                                            status = fileStore.CreateFile(out directoryHandle, out fileStatus, tempDirectory, AccessMask.GENERIC_READ, SMBLibrary.FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);

                                            if (status == NTStatus.STATUS_SUCCESS)
                                            {
                                                List<QueryDirectoryFileInformation> fileList;
                                                status = fileStore.QueryDirectory(out fileList, directoryHandle, "*", FileInformationClass.FileBothDirectoryInformation);
                                                foreach (FileBothDirectoryInformation file in fileList)
                                                {
                                                    if (!new List<string> { ".", "..", "desktop.ini", "Default" }.Contains(file.FileName))
                                                    {
                                                        if (Array.IndexOf(file.FileAttributes.ToString().Replace(" ", String.Empty).Split(','), "Directory") != -1)
                                                        {
                                                            if (i == 0)
                                                            {
                                                                sharedDirectories.Add(file.FileName.ToString());
                                                            }
                                                            else
                                                            {
                                                                sharedDirectories.Add(tempDirectory.ToString() + "\\" + file.FileName.ToString());
                                                            }
                                                            length++;
                                                        }
                                                        else if (Array.IndexOf(file.FileAttributes.ToString().Replace(" ", String.Empty).Split(','), "Archive") != -1)
                                                        {
                                                            if (i == 0)
                                                            {
                                                                sharedFiles.Add(file.FileName.ToString());
                                                            }
                                                            else
                                                            {
                                                                sharedFiles.Add(tempDirectory.ToString() + "\\" + file.FileName.ToString());
                                                            }
                                                        }
                                                    }
                                                }

                                                status = fileStore.CloseFile(directoryHandle);
                                            }
                                        }

                                        //Console.WriteLine("[?] DEBUG - Found " + sharedDirectories.Count + " Directories and " + sharedFiles.Count + " Files on \"\\\\" + targetMachine + "\\" + name + "\".");

                                        foreach (string tempFile in sharedFiles)
                                        {
                                            bool tempReadable = false;
                                            bool tempWritable = false;
                                            bool tempDeletable = false;
                                            bool tempDirectoryWritable = false;
                                            bool tempSeizable = false;
                                            string tempContent = null;
                                            object genericReadTempFileHandle = null;

                                            if (ruleFilter.Readable || ruleFilter.Content)
                                            {
                                                FileStatus fileStatus2;
                                                NTStatus result = fileStore.CreateFile(out genericReadTempFileHandle, out fileStatus2, tempFile, AccessMask.GENERIC_READ, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
                                                if (result == NTStatus.STATUS_SUCCESS)
                                                {
                                                    tempReadable = true;
                                                }
                                            }
                                            if (tempReadable && ruleFilter.Content)
                                            {
                                                byte[] tempData;
                                                status = fileStore.ReadFile(out tempData, genericReadTempFileHandle, 0, ((Convert.ToInt32(parsedParameters.maxFileSize) * 1024) * 1024));
                                                if (status == NTStatus.STATUS_SUCCESS)
                                                {
                                                    tempContent = System.Text.Encoding.Default.GetString(tempData);
                                                }
                                                fileStore.CloseFile(genericReadTempFileHandle);
                                            }
                                            if (ruleFilter.Writable)
                                            {
                                                FileStatus fileStatus3;
                                                object fileHandle;
                                                NTStatus result = fileStore.CreateFile(out fileHandle, out fileStatus3, tempFile, AccessMask.GENERIC_WRITE, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
                                                if (result == NTStatus.STATUS_SUCCESS)
                                                {
                                                    tempWritable = true;
                                                    fileStore.CloseFile(fileHandle);
                                                }
                                            }
                                            if (ruleFilter.Deletable)
                                            {
                                                FileStatus fileStatus4;
                                                object fileHandle;
                                                NTStatus result = fileStore.CreateFile(out fileHandle, out fileStatus4, tempFile, AccessMask.DELETE, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
                                                if (result == NTStatus.STATUS_SUCCESS)
                                                {
                                                    tempDeletable = true;
                                                    fileStore.CloseFile(fileHandle);
                                                }
                                            }
                                            if (ruleFilter.DirectoryWritable)
                                            {
                                                FileStatus fileStatus5;
                                                object directoryHandle2;
                                                string tempFileDirectory;

                                                if (tempFile.LastIndexOf('\\') == -1)
                                                {
                                                    tempFileDirectory = String.Empty;
                                                }
                                                else
                                                {
                                                    tempFileDirectory = tempFile.Substring(0, tempFile.LastIndexOf('\\'));
                                                }

                                                NTStatus result = fileStore.CreateFile(out directoryHandle2, out fileStatus5, tempFileDirectory, AccessMask.GENERIC_WRITE, SMBLibrary.FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);
                                                if (result == NTStatus.STATUS_SUCCESS)
                                                {
                                                    tempDirectoryWritable = true;
                                                    fileStore.CloseFile(directoryHandle2);
                                                }
                                            }
                                            if (ruleFilter.Seizable)
                                            {
                                                FileStatus fileStatus2;
                                                object fileHandlexxx;
                                                NTStatus result = fileStore.CreateFile(out fileHandlexxx, out fileStatus2, tempFile, AccessMask.WRITE_OWNER, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
                                                if (result == NTStatus.STATUS_SUCCESS)
                                                {
                                                    tempSeizable = true;
                                                    fileStore.CloseFile(fileHandlexxx);
                                                }
                                                else
                                                {
                                                    NTStatus result3 = fileStore.CreateFile(out fileHandlexxx, out fileStatus2, tempFile, AccessMask.WRITE_DAC, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
                                                    if (result3 == NTStatus.STATUS_SUCCESS)
                                                    {
                                                        tempSeizable = true;
                                                        fileStore.CloseFile(fileHandlexxx);
                                                    }
                                                }
                                            }

                                            foreach (RuleParser.Rule tempRule in parsedRules.Rules)
                                            {
                                                //Verifies if file's Write permissions match the rule
                                                if (tempRule.Writable != null)
                                                {
                                                    if (tempRule.Writable != tempWritable)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's Read permissions match the rule
                                                if (tempRule.Readable != null)
                                                {
                                                    if (tempRule.Readable != tempReadable)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's Delete permissions match the rule
                                                if (tempRule.Deletable != null)
                                                {
                                                    if (tempRule.Deletable != tempDeletable)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's directory Write permissions match the rule
                                                if (tempRule.DirectoryWritable != null)
                                                {
                                                    if (tempRule.DirectoryWritable != tempDirectoryWritable)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's directory Write permissions match the rule
                                                if (tempRule.Seizable != null)
                                                {
                                                    if (tempRule.Seizable != tempSeizable)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's Name matches the rule's regexes
                                                int failCounter = 0;
                                                if (tempRule.Filename != null)
                                                {
                                                    string actualTempFileName;
                                                    if (tempFile.LastIndexOf('\\') == -1)
                                                    {
                                                        actualTempFileName = tempFile;
                                                    }
                                                    else
                                                    {
                                                        actualTempFileName = tempFile.Substring(tempFile.LastIndexOf('\\') + 1);
                                                    }

                                                    foreach (string filenameRuleRegex in tempRule.Filename)
                                                    {
                                                        Regex r = new Regex(filenameRuleRegex, RegexOptions.IgnoreCase);
                                                        Match m = r.Match(actualTempFileName);

                                                        if (!m.Success)
                                                        {
                                                            failCounter++;
                                                        }
                                                    }

                                                    if (failCounter == tempRule.Filename.Count)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's Path matches the rule's regexes
                                                failCounter = 0;
                                                if (tempRule.Path != null)
                                                {
                                                    string filePath;
                                                    if (tempFile.LastIndexOf('\\') == -1)
                                                    {
                                                        continue;
                                                    }
                                                    else
                                                    {
                                                        filePath = tempFile.Substring(0, tempFile.LastIndexOf('\\'));
                                                    }

                                                    foreach (string pathRuleRegex in tempRule.Path)
                                                    {
                                                        Regex r = new Regex(pathRuleRegex, RegexOptions.IgnoreCase);
                                                        Match m = r.Match(filePath);

                                                        if (!m.Success)
                                                        {
                                                            failCounter++;
                                                        }
                                                    }

                                                    if (failCounter == tempRule.Filename.Count)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's Extension matches the rule's regexes
                                                failCounter = 0;
                                                if (tempRule.Extension != null)
                                                {
                                                    string actualTempFileExtension;
                                                    if (tempFile.LastIndexOf('.') == -1)
                                                    {
                                                        continue;
                                                    }
                                                    else
                                                    {
                                                        actualTempFileExtension = tempFile.Substring(tempFile.LastIndexOf('.') + 1);
                                                    }

                                                    foreach (string fileExtensionRule in tempRule.Extension)
                                                    {
                                                        //Old extension comparison using regex, might be useful in the future
                                                        //Regex r = new Regex(fileExtensionRuleRegex, RegexOptions.IgnoreCase);
                                                        //Match m = r.Match(actualTempFileExtension);

                                                        //if (!m.Success)
                                                        //{
                                                        //    failCounter++;
                                                        //}

                                                        if (actualTempFileExtension != fileExtensionRule)
                                                        {
                                                            failCounter++;
                                                        }
                                                    }

                                                    if (failCounter == tempRule.Extension.Count)
                                                    {
                                                        continue;
                                                    }
                                                }

                                                //Verifies if file's Content matches the rule's regexes
                                                failCounter = 0;
                                                if (tempRule.Content != null)
                                                {
                                                    if (!tempReadable || String.IsNullOrEmpty(tempContent))
                                                    {
                                                        continue;
                                                    }
                                                    else
                                                    {
                                                        foreach (string fileContentRuleRegex in tempRule.Content)
                                                        {
                                                            Regex r = new Regex(fileContentRuleRegex, RegexOptions.IgnoreCase);
                                                            Match m = r.Match(tempContent);

                                                            if (!m.Success)
                                                            {
                                                                failCounter++;
                                                            }
                                                        }

                                                        if (failCounter == tempRule.Content.Count)
                                                        {
                                                            continue;
                                                        }
                                                    }
                                                }

                                                lock (fileLock)
                                                {
                                                    using (StreamWriter writer = File.AppendText($"{parsedParameters.output}.txt"))
                                                    {
                                                        writer.WriteLine($"\"\\\\{targetMachine}\\{name}\\{tempFile}\" is a positive for \"{tempRule.Name}\"");
                                                    }
                                                }
                                            }
                                        }
                                        status = fileStore.Disconnect();
                                    }
                                    else
                                    {
                                        Console.WriteLine($"[+] Found share: \"\\\\{targetMachine}\\{name}\" with [NO ACCESS].");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine($"[-] {IPAddress.Parse(targetMachine)} authentication failed.");
                            }
                            client.Disconnect();
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] " + IPAddress.Parse(targetMachine) + " is unreachable on port 445.");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[!] Something went wrong: {e.Message}");
                    throw;
                }
            });

            stopwatch.Stop();
            TimeSpan elapsedTime = stopwatch.Elapsed;
            Console.WriteLine($"[+] Finished scanning all targets ({elapsedTime.TotalSeconds:F3}s).");
            Console.WriteLine($"[+] Rules Matches saved to \"{parsedParameters.output}.txt\", good luck.");
        }
    }
}
