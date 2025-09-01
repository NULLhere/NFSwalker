# NFSwalker
A modern user-space NFS client with proxy support



<h1>ABOUT</h1>

This tool is a user-space NFS client. During penetration testing or red teaming activities, mount has many limitations and nfspy is still stuck on Python 2. Therefore, this project was created to provide a more modern alternative to what is typically used to test NFS shares.

It currently supports: NFSv3, NFSv4, and NFSv4.1.
It allows the use of a proxy, directory listing, file reading and writing without mounting the remote share locally. Additionally, it performs user spoofing by letting the tester choose which UID, GID, and hostname to use when accessing the NFS server in case of whitelisting.
Feel free to share what others features may be useful!

<h1>PREREQUISITES</h1>
PySocks==1.7.1




<h1>EXAMPLES & USAGE</h1>


Supported commands: 
- perms: to list ACLs
- read: to read files
- ls: to list the content of a folder
- write: to write a file on the remote share


https://github.com/user-attachments/assets/9531b8f0-2355-4626-bcd9-b13df0afbbd6



When this command is executed, two types of permissions are distinguished:

- those of the folders and files, identified by MODE
- those of the share, identified by GRANTED

What does this mean? Let’s suppose we receive this output from an NFS share on a Windows Server:

```
Checking permissions for: /
File type: 2
Mode: 0777          
Owner: SYSTEM@NT AUTHORITY
Owner Group: SYSTEM@NT AUTHORITY

Access check results:
Requested: 0x3f (all permissions)
Supported: 0x1f
Granted:   0x03

Permission breakdown:
READ:    ✓
LOOKUP:  ✓
MODIFY:  ✗
EXTEND:  ✗
DELETE:  ✗
EXECUTE: ✗

🔴 READ-ONLY: Path appears to be read-only
```

Theoretically, with 777 (which is how Windows maps and translates the ACLs set by icacls for the user in use into Unix-style permissions), this user should be able to do everything, correct?
Nope! Because the share configuration only allows READ and LOOKUP operations.
Fundamentally, both types of permissions must match for the user to be able to perform actions.

That said, for a Linux server it’s straightforward: the UID and GID correspond to the owners of the resources being requested. Once obtained, you can impersonate that identity and access the target content.
For a Windows server, it’s more complex—especially when detailed FATTR4_ACL attributes are not enabled, as UID and GID are not returned.
Assuming:

- anonymous access is disabled,
- security is set to SYS,
- specific UID and GID mappings are configured,

then—thanks to the brute-force module (explained later) and some patience—it is still possible to get access to the target



### PROXY
***

In addition to being compatible with https://github.com/NULLhere/Proxando for traffic redirection, the tool also includes a built-in switch for SOCKS proxy integration. This makes it portable and easy to deploy in different environments.

However, keep in mind that if the NFS server is configured to accept connections only from privileged ports, and you’re using a proxy instead of a direct connection, then the proxy itself must use privileged ports to successfully connect to the server.


### BRUTEFORCE
***
This feature was designed for scenarios where anonymous access to the NFS share is not allowed, and no valid user credentials are known to access it.
Fundamentally, the tool performs an iterative brute-force over a list of provided UID and GID values, until it identifies one of the following:

- A UID/GID combination that grants at least readdir permission
- A UID/GID combination that grants at least lookup permission
- A UID/GID combination that grants both readdir and lookup permissions


https://github.com/user-attachments/assets/71bc58b5-b9e7-4e9e-9bf3-c1ba72fd8728


<h1>LIMITATIONS AND ROADMAP</h1>
Delete and Execute operations are not supported.

Support for NFSv2 and NFSv4.2 is planned for future releases. Currently, they are not implemented because, in most real-world environments, servers expose other NFS version (e.g., NFSv3 or NFSv4.1) for compatibility.

A module for Kerberos-based authentication is also planned, to handle scenarios where a Windows Server NFS share is configured to require it.


<h1>ABOUT ISSUES</h1>
If you find any issues, please report them in as much detail as possible so I can try to reproduce them in my environment! Include things like: the software involved, Wireshark traffic captures, the proxy you are using, the scenario, and anything else that might help

I don't know when (or if) I will be able to fix them, so feel free to open a pull request with a fix, I will review it as soon as I can!(:
