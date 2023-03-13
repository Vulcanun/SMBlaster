using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Linq;
using System.Net;

namespace SMBlaster
{
    public class CommandLineParser
    {
        public static List<string> GetIPRangeFromCIDR(string cidrString)
        {
            string[] cidrParts = cidrString.Split('/');
            if (cidrParts.Length != 2)
            {
                throw new ArgumentException("Invalid CIDR notation string");
            }

            string ipAddress = cidrParts[0];
            int prefixLength = int.Parse(cidrParts[1]);

            if (prefixLength < 0 || prefixLength > 32)
            {
                throw new ArgumentException("Invalid prefix length");
            }

            if (cidrParts[1] == "32")
            {
                return new List<string>() { cidrParts[0] };
            }

            uint ip = IPAddressToUInt(ipAddress);
            uint mask = PrefixLengthToMask(prefixLength);

            uint network = ip & mask;
            uint broadcast = network | ~mask;

            List<string> ipList = new List<string>();
            for (uint i = network + 1; i < broadcast; i++)
            {
                string nextIP = UIntToIPAddress(i);
                ipList.Add(nextIP);
            }

            return ipList;
        }

        private static uint IPAddressToUInt(string ipAddress)
        {
            byte[] ipBytes = ipAddress.Split('.')
                .Select(s => byte.Parse(s))
                .Reverse()
                .ToArray();
            return BitConverter.ToUInt32(ipBytes, 0);
        }

        private static string UIntToIPAddress(uint ip)
        {
            byte[] ipBytes = BitConverter.GetBytes(ip);
            return string.Join(".", ipBytes.Reverse());
        }

        private static uint PrefixLengthToMask(int prefixLength)
        {
            uint mask = 0xffffffff;
            mask = mask << (32 - prefixLength);
            return mask;
        }

        public static List<string> GetIPsFromHostname(string hostName)
        {
            List<string> ipAddresses = new List<string>();
            IPAddress[] addresses = Dns.GetHostAddresses(hostName);
            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    ipAddresses.Add(address.ToString());
                }
            }
            return ipAddresses;
        }

        public List<string> parseTargets(string[] rawTargets)
        {
            List<string> finalTargets = new List<string>();
            string cidrPattern = @"^(\d{1,3}\.){3}\d{1,3}/(0|[1-2]?\d|3[0-2])$";
            string hostnamePattern = @"[a-zA-Z]+";

            foreach (string rawTarg in rawTargets)
            {
                if (String.IsNullOrEmpty(rawTarg))
                {
                    continue;
                }

                //resolves CIDR notations and explodes their contents
                Match match = Regex.Match(rawTarg, cidrPattern);
                if (match.Success)
                {
                    List<string> explodedCIDR = GetIPRangeFromCIDR(rawTarg);
                    finalTargets = finalTargets.Union(explodedCIDR).ToList();
                    continue;
                }

                //resolves hostnames into IP addresses
                Match match2 = Regex.Match(rawTarg, hostnamePattern);
                if (match2.Success)
                {
                    List<string> explodedHostname = GetIPsFromHostname(rawTarg);
                    finalTargets = finalTargets.Union(explodedHostname).ToList();
                    continue;
                }
                
                finalTargets.Add(rawTarg);
            }

            return finalTargets;
        }

        public void printHelp()
        {
            Console.WriteLine("Usage: SMBlaster.exe [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("--domain or -d: Specify the user's domain to use for authentication.");
            Console.WriteLine("--username or -u: Specify the username to use for authentication.");
            Console.WriteLine("--password or -p: Specify the password to use for authentication.");
            Console.WriteLine("--target or -t: Specify the targets. If a file, each line should be either an IP Address, a CIDR notation or a hostname.");
            Console.WriteLine("--rules or -r: Specify the rules file to use.");
            Console.WriteLine("--output or -o: Specify the output file.");
            Console.WriteLine("--maxFileSize or -s: Specify the maximum file size (in Mb.) for content scanning.");
            Console.WriteLine("--method or -m: Specify the method to use for execution. Accepted Values: Simple - Files are not scanned, only does share discovery - and Complete - Both Files and Shares are scanned.");
            Environment.Exit(1);
        }

        public class ParsedParameters
        {
            public string domain;
            public string username;
            public string password;
            public List<string> target;
            public string rules = "rules.json";
            public string output = "SMBlaster Report - " + DateTime.Now.ToString("yyyyMMddHHmmss");
            public string method = "full";
            public string maxFileSize = "1";
        }

        public ParsedParameters parseParameters(string[] args)
        {
            ParsedParameters parsed = new ParsedParameters();
            int argCounter = 0;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--domain":
                    case "-d":
                        parsed.domain = args[i + 1];
                        i++;
                        argCounter++;
                        break;
                    case "--username":
                    case "-u":
                        parsed.username = args[i + 1];
                        i++;
                        argCounter++;
                        break;
                    case "--password":
                    case "-p":
                        parsed.password = args[i + 1];
                        i++;
                        argCounter++;
                        break;
                    case "--target":
                    case "-t":
                        string[] tempTargArray = new string[0];
                        if (File.Exists(args[i + 1]))
                        {
                            tempTargArray = File.ReadAllLines(args[i + 1]);
                        }
                        else
                        {
                            tempTargArray = tempTargArray.Append(args[i + 1]).ToArray();
                        }
                        parsed.target = parseTargets(tempTargArray);
                        i++;
                        argCounter++;
                        break;
                    case "--rules":
                    case "-r":
                        if (!File.Exists(args[i + 1])){
                            Console.WriteLine("Invalid rules file received, \"" + args[i + 1] + "\" doesn't exist.");
                            printHelp();
                        }
                        parsed.rules = args[i + 1];
                        i++;
                        break;
                    case "--output":
                    case "-o":
                        parsed.output = args[i + 1];
                        i++;
                        break;
                    case "--method":
                    case "-m":
                        if (args[i + 1].ToLower() == "simple")
                        {
                            parsed.method = "simple";
                        }
                        else if (args[i + 1].ToLower() == "full")
                        {
                            parsed.method = "full";
                        }
                        else
                        {
                            Console.WriteLine($"Invalid method received: {args[i+1]}.\n");
                            printHelp();
                            break;
                        }
                        i++;
                        break;
                    case "--maxFileSize":
                    case "-s":
                        parsed.maxFileSize = args[i + 1];
                        i++;
                        break;
                    case "--help":
                    case "-h":
                        printHelp();
                        break;
                    default:
                        Console.WriteLine($"Unrecognized parameter: {args[i]}.\n");
                        printHelp();
                        break;
                }
            }

            if (argCounter != 4)
            {
                Console.WriteLine("Did not receive every required parameter.\n");
                printHelp();
            }

            return parsed;
        }
    }
}
