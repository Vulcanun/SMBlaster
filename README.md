```
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
```
       
SMBlaster is a SMB Share scanner with modular rule-based content check validation.

# Usage
SMBlaster allows penetration testers and other security professionals to quickly scan their network for available SMB Shares and, whenever readable, spidering through each and every single file contained on those to identify known exploitation scenarios. Below we can see an example of how modular SMBlaster's rules are and they could find on your network:

```json
{
  "Name": "Writable PHP Config File",
  "Description": "PHP generally uses a default config file name, where domain and database credentials might be stored. Write permissions on these files allow for the full compromise of the application through command execution.",
  "Filename": [
    "php.ini"
  ],
  "Writable": true
}
```

The rule above is rather simple, yet effective. SMBlaster will look through every single file accessible on a given SMB Share looking for files named "php.ini" and make sure they are writable, reporting successful matches so the operator can actively exploit that php service inserting commands on to the "php.ini" file.

SMBlaster allows the operator to customize these rules and create custom scenarios specific to their needs and their networks. Here are all of the properties that can be used (in any combination with one another) for custom rules:

| Field             | Expected Value        | Example                                                                 | Description                                                                                                                                                                                               |
|-------------------|-----------------------|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Name              | String                | "Name": "Writable PHP Config File"                                      | This is the name of the rule itself, it will not be used for any file or share validation, but will be written to the output file if the other properties result in a successful match.                   |
| Description       | String                | "Description": "Really cool description!"                               | Currently unused. Simply adds context to those reading the rules.                                                                                                                                         |
| Filename          | List of Regex Filters | "Filename": [     "php.ini",     "web.config" ]                         | SMBlaster will look for files where the filename matches at least one of the Regex Filters passed.                                                                                                        |
| Extension         | List of Strings       | "Extension": [     "txt",     "csv" ]                                   | SMBlaster will look for files where the last extension matches at least one of the strings passed.                                                                                                        |
| Content           | List of Regex Filters | "Content": [     "password",     "pwd" ]                                | SMBlaster will read a file's content, looking for at least one match of the Regex Filters passed.                                                                                                         |
| Path              | List of Regex Filters | "Content": [     "C:\\\\Users\\\\Public",     "D:\\\\Users\\\\Public" ] | SMBlaster will read a file's full path (excluding the filename itself), looking for at least one match of the Regex Filters passed.                                                                       |
| Readable          | Boolean               | "Readable": true                                                        | SMBlaster will attempt to establish an SMB Connection estating the GENERIC_READ Access Mask, the boolean outcome of that operation will be compared to the passed value.                                  |
| Writable          | Boolean               | "Writable": true                                                        | SMBlaster will attempt to establish an SMB Connection estating the GENERIC_WRITE Access Mask, the boolean outcome of that operation will be compared to the passed value.                                 |
| Deletable         | Boolean               | "Deletable": true                                                       | SMBlaster will attempt to establish an SMB Connection estating the DELETE Access Mask, the boolean outcome of that operation will be compared to the passed value.                                        |
| DirectoryWritable | Boolean               | "DirectoryWritable": true                                               | SMBlaster will attempt to establish an SMB Connection estating the GENERIC_WRITE Access Mask to the file's current directory, the boolean outcome of that operation will be compared to the passed value. |
| Seizable          | Boolean               | "Seizable": true                                                        | SMBlaster will attempt to establish an SMB Connection estating the WRITE_OWNER and the WRITE_DAC Access Masks, the boolean outcome of that operation will be compared to the passed value.                |

# Output
SMBlaster can be used with two different objectives:

If all you want is to map your network's SMB Shares, make use of the "simple" execution method. This will not make use of the rules but will print on the console every share found and the permission the passed credentials have on it. Here's what that looks like:
```
[*] Starting Simple scan on 1 targets.
[+] Found share: "\\192.168.15.24\ADMIN$" with [NO ACCESS].
[+] Found share: "\\192.168.15.24\C$" with [NO ACCESS].
[+] Found share: "\\192.168.15.24\Users" with [READ].
[+] Finished scanning all targets (29.981s).
[+] Rules Matches saved to "SMBlaster Report - 20230314005506.txt", good luck.
```

If you want to make full use of SMBlaster's modular rule-based content verification engine, all you have to do is use the "full" execution method. This will take longer but will probably find some valuable goodies on your network. Here's what the output file will (hopefully) look like:
```
"\\192.168.15.24\Users\SMBlaster\dale.exe" is a positive for "Readable Steel Runas Executable"
"\\192.168.15.24\Users\SMBlaster\admin2.bat" is a positive for "Writable Scripts"
"\\192.168.15.24\Users\SMBlaster\privkey.txt" is a positive for "Readable SSH Private Key Files"
"\\192.168.15.24\Users\SMBlaster\SAM" is a positive for "Readable SAM/SYSTEM/SECURITY Dumps"
"\\192.168.15.24\Users\SMBlaster\SYSTEM" is a positive for "Readable SAM/SYSTEM/SECURITY Dumps"
"\\192.168.15.24\Users\SMBlaster\Unattend.xml" is a positive for "Readable Windows Unattended Install Files"
"\\192.168.15.24\Users\SMBlaster\web.config.bkp" is a positive for "Readable Backup Files"
```

# Help
```
Usage: SMBlaster.exe [options]
Options:
--domain or -d: Specify the user's domain to use for authentication.
--username or -u: Specify the username to use for authentication.
--password or -p: Specify the password to use for authentication.
--target or -t: Specify the targets. If a file, each line should be either an IP Address, a CIDR notation or a hostname.
--rules or -r: Specify the rules file to use.
--output or -o: Specify the output file.
--maxFileSize or -s: Specify the maximum file size (in Mb.) for content scanning.
--method or -m: Specify the method to use for execution. Accepted Values: Simple - Files are not scanned, only does share discovery - and Complete - Both Files and Shares are scanned.
```
