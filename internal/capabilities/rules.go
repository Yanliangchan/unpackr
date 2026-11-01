package capabilities

import "github.com/Yanliangchan/unpackr/pkg/models"

// Group is one stage of an API relationship. A group is satisfied when any of
// its APIs is present.
type Group struct {
	Label string
	APIs  []string
}

// StrPattern matches a case-insensitive substring of an extracted string.
type StrPattern struct {
	Substr   string
	Label    string
	Strength string // strong | moderate | weak
}

// BytePattern matches raw bytes such as cryptographic constants.
type BytePattern struct {
	Needle   []byte
	Label    string
	Strength string
}

// Rule describes one capability. Rules only ever claim that the file
// references or contains something, never that it does something.
type Rule struct {
	ID, Name, Category string
	Attack             []string
	// Summary completes the sentence "<evidence>, consistent with ...".
	Summary  string
	Severity models.Severity
	OS       []string // pe, elf, macho; empty means all
	Groups   []Group
	// Need is the number of groups that must be present for an import-based
	// report. Zero means all of them.
	Need int
	// Complete and Partial are the signal strengths when every group, or only
	// Need groups, are present.
	Complete, Partial string
	Strings           []StrPattern
	Bytes             []BytePattern
	// Benign says where this pattern is common and harmless.
	Benign string
}

func g(label string, apis ...string) Group { return Group{Label: label, APIs: apis} }

// Rules is the built-in rule set. API names are listed without the A/W
// suffix; matching handles both.
var Rules = []Rule{
	// ---- network communication
	{ID: "network.client.winsock", Name: "Network client (sockets)", Category: "network communication", Attack: []string{"T1095"},
		Summary: "software able to open outbound TCP/UDP connections", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("initialise", "WSAStartup"), g("connect", "connect", "WSAConnect", "WSASocket", "socket"), g("transfer", "send", "recv", "WSASend", "WSARecv", "sendto", "recvfrom")},
		Need:   2, Complete: "moderate", Partial: "weak", Benign: "Nearly every networked program uses these."},
	{ID: "network.client.http", Name: "HTTP client", Category: "network communication", Attack: []string{"T1071.001"},
		Summary: "software able to make HTTP(S) requests", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("open session", "InternetOpen", "WinHttpOpen"), g("connect", "InternetConnect", "WinHttpConnect", "InternetOpenUrl"), g("request", "HttpOpenRequest", "HttpSendRequest", "WinHttpOpenRequest", "WinHttpSendRequest", "InternetReadFile", "WinHttpReadData")},
		Need:   2, Complete: "moderate", Partial: "weak", Benign: "Updaters, telemetry and installers all use these APIs."},
	{ID: "network.download", Name: "Download to disk", Category: "network communication", Attack: []string{"T1105"},
		Summary: "software able to fetch a remote file and store it locally", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:   []Group{g("download", "URLDownloadToFile", "URLDownloadToCacheFile", "BITSJobAddFile")},
		Complete: "moderate", Benign: "Installers and updaters download files by design."},
	{ID: "network.server", Name: "Network listener", Category: "network communication", Attack: []string{"T1095"},
		Summary: "software able to accept inbound connections", Severity: models.SeverityLow, OS: []string{"pe", "elf", "macho"},
		Groups:   []Group{g("bind", "bind"), g("listen", "listen"), g("accept", "accept", "accept4", "WSAAccept")},
		Complete: "moderate", Benign: "Any server, including local IPC helpers, does this."},
	{ID: "network.client.posix", Name: "Network client (sockets)", Category: "network communication", Attack: []string{"T1095"},
		Summary: "software able to open outbound connections", Severity: models.SeverityLow, OS: []string{"elf", "macho"},
		Groups: []Group{g("socket", "socket"), g("connect", "connect"), g("resolve", "getaddrinfo", "gethostbyname", "gethostbyname2", "inet_pton", "inet_addr")},
		Need:   2, Complete: "moderate", Partial: "weak", Benign: "Common to nearly all networked programs."},

	// ---- process creation / execution
	{ID: "exec.process", Name: "Process creation", Category: "process creation", Attack: []string{"T1106"},
		Summary: "software able to start other programs", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("create", "CreateProcess", "CreateProcessAsUser", "CreateProcessWithLogon", "CreateProcessWithToken", "ShellExecute", "ShellExecuteEx", "WinExec", "NtCreateUserProcess", "RtlCreateUserProcess")},
		Complete: "weak", Benign: "Launchers, installers and shells; extremely common."},
	{ID: "exec.process.posix", Name: "Process creation", Category: "process creation", Attack: []string{"T1106", "T1059.004"},
		Summary: "software able to start other programs or shell commands", Severity: models.SeverityLow, OS: []string{"elf", "macho"},
		Groups:   []Group{g("spawn", "execve", "execv", "execvp", "execl", "execlp", "posix_spawn", "posix_spawnp", "system", "popen")},
		Complete: "weak", Benign: "Extremely common."},
	{ID: "exec.shell-strings", Name: "Shell or script interpreter command lines", Category: "process creation", Attack: []string{"T1059"},
		Summary: "software that carries command lines for a shell or script host", Severity: models.SeverityMedium,
		Strings: []StrPattern{
			{"cmd.exe /c", "cmd.exe /c", "moderate"}, {"cmd /c", "cmd /c", "moderate"}, {"powershell -", "powershell switch", "moderate"},
			{"powershell.exe -", "powershell.exe switch", "moderate"}, {"-encodedcommand", "encoded PowerShell", "moderate"}, {"-executionpolicy bypass", "execution policy bypass", "moderate"},
			{"wscript.exe", "wscript", "weak"}, {"mshta ", "mshta", "moderate"}, {"/bin/sh -c", "sh -c", "weak"}, {"/bin/bash -c", "bash -c", "weak"},
		}, Benign: "Installers and build tools legitimately run commands."},
	{ID: "exec.lolbin-strings", Name: "Living-off-the-land binary references", Category: "process creation", Attack: []string{"T1218"},
		Summary: "software that names built-in utilities often abused to run or fetch code", Severity: models.SeverityMedium, OS: []string{"pe"},
		Strings: []StrPattern{
			{"regsvr32", "regsvr32", "weak"}, {"rundll32", "rundll32", "weak"}, {"certutil -urlcache", "certutil download", "moderate"}, {"certutil -decode", "certutil decode", "moderate"},
			{"bitsadmin /transfer", "bitsadmin transfer", "moderate"}, {"msiexec /i http", "msiexec remote install", "moderate"},
		}, Benign: "Installers call regsvr32 and rundll32 routinely."},

	// ---- obfuscation
	{ID: "evasion.dynamic-resolve", Name: "Run-time symbol resolution", Category: "obfuscation", Attack: []string{"T1027.007"},
		Summary: "software that looks up functions by name while running, which hides them from the import table", Severity: models.SeverityLow,
		Groups: []Group{g("resolve by name", "dlsym", "GetProcAddress", "LdrGetProcedureAddress", "dlvsym")},
		Need:   1, Complete: "weak", Benign: "Plugin systems, language runtimes, graphics and audio libraries and compatibility shims resolve symbols this way."},

	// ---- managed (.NET) code. API names are the "Type.Member" pairs a
	// managed assembly refers to (property getters appear as get_Name).
	{ID: "dotnet.reflective-load", Name: "Loading assemblies at run time", Category: "obfuscation", Attack: []string{"T1620"},
		Summary: "managed code that loads another assembly while running, which can hide that assembly from static inspection", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:   []Group{g("load assembly", "Assembly.Load", "Assembly.LoadFrom", "Assembly.LoadFile", "Assembly.UnsafeLoadFrom", "AppDomain.Load", "Assembly.LoadWithPartialName")},
		Complete: "moderate", Benign: "Plugin hosts, dependency injection containers, test runners and ASP.NET all load assemblies this way."},
	{ID: "dotnet.process", Name: "Process creation (.NET)", Category: "process creation", Attack: []string{"T1106", "T1059"},
		Summary: "managed code able to start other programs", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("start process", "Process.Start")},
		Complete: "moderate", Benign: "Launchers, installers and tools that open documents call Process.Start."},
	{ID: "dotnet.download", Name: "Download in managed code", Category: "network communication", Attack: []string{"T1105"},
		Summary: "managed code able to fetch remote content", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:   []Group{g("download", "WebClient.DownloadString", "WebClient.DownloadData", "WebClient.DownloadFile", "WebClient.DownloadStringAsync", "WebClient.DownloadFileAsync", "WebClient.DownloadDataAsync", "HttpClient.GetStringAsync", "HttpClient.GetByteArrayAsync", "HttpClient.GetStreamAsync")},
		Complete: "moderate", Benign: "Updaters and API clients download content as a matter of course."},
	{ID: "dotnet.web-request", Name: "Web requests (.NET)", Category: "network communication", Attack: []string{"T1071.001"},
		Summary: "managed code able to make HTTP(S) requests", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("request", "WebRequest.Create", "HttpWebRequest.GetResponse", "HttpClient.SendAsync", "HttpClient.PostAsync", "HttpClient.GetAsync")},
		Complete: "weak", Benign: "Nearly any networked .NET program."},
	{ID: "dotnet.socket", Name: "Network sockets (.NET)", Category: "network communication", Attack: []string{"T1095"},
		Summary: "managed code able to open TCP connections", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("connect", "TcpClient.Connect", "TcpClient.ConnectAsync", "Socket.Connect", "Socket.ConnectAsync", "TcpClient..ctor", "Socket..ctor")},
		Complete: "weak", Benign: "Any program with a network connection."},
	{ID: "dotnet.decode-decrypt", Name: "Decoding and decrypting data (.NET)", Category: "obfuscation", Attack: []string{"T1140"},
		Summary: "managed code that decodes base64 and decrypts data, a pattern used to hide payloads and strings", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("decode", "Convert.FromBase64String"), g("decrypt", "SymmetricAlgorithm.CreateDecryptor", "Aes.CreateDecryptor", "Rijndael.CreateDecryptor", "DES.CreateDecryptor", "TripleDES.CreateDecryptor", "RijndaelManaged..ctor", "AesManaged..ctor", "AesCryptoServiceProvider..ctor", "DESCryptoServiceProvider..ctor")},
		Complete: "weak", Benign: "Configuration, licensing and storage code decodes and decrypts too; this is a pattern, not proof of concealment."},
	{ID: "dotnet.registry", Name: "Registry writes (.NET)", Category: "persistence", Attack: []string{"T1112"},
		Summary: "managed code able to write registry values", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("write registry", "RegistryKey.SetValue", "Registry.SetValue", "RegistryKey.CreateSubKey")},
		Complete: "weak", Benign: "Installers and settings code use the registry."},
	{ID: "dotnet.debugger", Name: "Debugger detection (.NET)", Category: "anti-debugging", Attack: []string{"T1622"},
		Summary: "managed code that checks whether a debugger is attached", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("check", "Debugger.IsAttached", "Debugger.get_IsAttached", "Debugger.IsLogging")},
		Complete: "weak", Benign: "Diagnostics and assertions check this too."},
	{ID: "dotnet.native-exec", Name: "Calling into native memory (.NET)", Category: "process injection", Attack: []string{"T1620"},
		Summary: "managed code that allocates native memory and turns it into something callable, the shape of running shellcode", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:   []Group{g("allocate", "Marshal.AllocHGlobal", "Marshal.AllocCoTaskMem"), g("make callable", "Marshal.GetDelegateForFunctionPointer", "Marshal.GetFunctionPointerForDelegate")},
		Complete: "weak", Benign: "Interop wrappers around native libraries."},
	{ID: "dotnet.screen-capture", Name: "Screen capture (.NET)", Category: "collection", Attack: []string{"T1113"},
		Summary: "managed code able to copy the screen", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("capture", "Graphics.CopyFromScreen")},
		Complete: "weak", Benign: "Screenshot tools, remote support and help software."},

	// ---- process injection
	{ID: "inject.classic", Name: "Remote process memory write and execution", Category: "process injection", Attack: []string{"T1055"},
		Summary: "the allocate, write and run-remotely sequence used by process injection", Severity: models.SeverityHigh, OS: []string{"pe"},
		Groups: []Group{g("open target", "OpenProcess", "NtOpenProcess"), g("allocate in target", "VirtualAllocEx", "NtAllocateVirtualMemory", "NtMapViewOfSection", "ZwMapViewOfSection"), g("write to target", "WriteProcessMemory", "NtWriteVirtualMemory"), g("execute in target", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "SetThreadContext")},
		Need:   3, Complete: "moderate", Partial: "weak", Benign: "Debuggers, game overlays, accessibility tools and security products use these APIs."},
	{ID: "inject.hollowing", Name: "Process hollowing pattern", Category: "process injection", Attack: []string{"T1055.012"},
		Summary: "the unmap, rewrite and resume sequence used for process hollowing", Severity: models.SeverityHigh, OS: []string{"pe"},
		Groups:   []Group{g("create suspended", "CreateProcess"), g("unmap original", "NtUnmapViewOfSection", "ZwUnmapViewOfSection"), g("write new image", "WriteProcessMemory", "NtWriteVirtualMemory"), g("redirect and resume", "SetThreadContext", "NtSetContextThread", "ResumeThread", "NtResumeThread")},
		Complete: "moderate", Benign: "Rare outside malware and some debuggers or packers."},
	{ID: "inject.dll", Name: "DLL loading in another process", Category: "process injection", Attack: []string{"T1055.001"},
		Summary: "the remote-thread LoadLibrary sequence used for DLL injection", Severity: models.SeverityHigh, OS: []string{"pe"},
		Groups:   []Group{g("write path", "WriteProcessMemory"), g("remote thread", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx"), g("loader address", "LoadLibrary", "GetProcAddress", "GetModuleHandle")},
		Complete: "weak", Benign: "Needs corroboration from the classic pattern; each API is common alone."},
	{ID: "inject.ptrace", Name: "Debugging interface for another process", Category: "process injection", Attack: []string{"T1055.008"},
		Summary: "software able to attach to and modify other processes", Severity: models.SeverityMedium, OS: []string{"elf", "macho"},
		Groups: []Group{g("trace", "ptrace"), g("memory", "process_vm_writev", "process_vm_readv", "mach_vm_write", "vm_write", "task_for_pid")},
		Need:   1, Complete: "moderate", Partial: "weak", Benign: "Debuggers, profilers, crash reporters and container tools."},

	// ---- persistence
	{ID: "persist.registry-run", Name: "Registry autorun entries", Category: "persistence", Attack: []string{"T1547.001"},
		Summary: "software able to write registry values and naming an autorun location", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:  []Group{g("write registry", "RegSetValueEx", "RegCreateKeyEx", "RegSetKeyValue", "NtSetValueKey")},
		Strings: []StrPattern{{"currentversion\\run", "Run key path", "moderate"}, {"currentversion\\runonce", "RunOnce key path", "moderate"}, {"\\start menu\\programs\\startup", "Startup folder path", "moderate"}},
		Need:    1, Complete: "weak", Benign: "Installers register autostart entries legitimately."},
	{ID: "persist.service", Name: "Windows service management", Category: "persistence", Attack: []string{"T1543.003"},
		Summary: "software able to create or control Windows services", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups: []Group{g("service manager", "OpenSCManager"), g("create service", "CreateService"), g("start service", "StartService", "StartServiceCtrlDispatcher")},
		Need:   2, Complete: "moderate", Partial: "weak", Benign: "Any program that is itself a service imports StartServiceCtrlDispatcher."},
	{ID: "persist.scheduled-task", Name: "Scheduled task references", Category: "persistence", Attack: []string{"T1053.005"},
		Summary: "software that references the task scheduler interfaces", Severity: models.SeverityMedium, OS: []string{"pe"},
		Strings: []StrPattern{{"schtasks /create", "schtasks /create", "moderate"}, {"schtasks.exe /create", "schtasks.exe /create", "moderate"}, {"schedule.service", "Schedule.Service COM name", "weak"}, {"itaskservice", "ITaskService", "weak"}},
		Benign:  "Installers and updaters register tasks."},
	{ID: "persist.cron", Name: "Cron and shell profile references", Category: "persistence", Attack: []string{"T1053.003", "T1546.004"},
		Summary: "software that names cron locations or shell start-up files", Severity: models.SeverityMedium, OS: []string{"elf", "macho"},
		Strings: []StrPattern{{"/etc/cron", "/etc/cron*", "moderate"}, {"crontab", "crontab", "weak"}, {"/etc/rc.local", "rc.local", "moderate"}, {".bashrc", ".bashrc", "weak"}, {".bash_profile", ".bash_profile", "weak"}, {"/etc/systemd/system", "systemd unit directory", "moderate"}, {"launchagents", "LaunchAgents", "moderate"}, {"launchdaemons", "LaunchDaemons", "moderate"}},
		Benign:  "Installers and shells."},

	// ---- credential access
	{ID: "cred.lsass", Name: "LSASS or credential store access", Category: "credential access", Attack: []string{"T1003.001"},
		Summary: "software able to dump process memory and naming the credential-holding process", Severity: models.SeverityHigh, OS: []string{"pe"},
		Groups:  []Group{g("dump", "MiniDumpWriteDump", "NtReadVirtualMemory", "ReadProcessMemory")},
		Strings: []StrPattern{{"lsass.exe", "lsass.exe", "moderate"}, {"sekurlsa", "sekurlsa", "strong"}, {"wdigest", "wdigest", "weak"}, {"seDebugPrivilege", "SeDebugPrivilege", "weak"}},
		Need:    1, Complete: "weak", Benign: "Crash reporters and security tools legitimately dump memory."},
	{ID: "cred.password-stores", Name: "Credential store APIs", Category: "credential access", Attack: []string{"T1555"},
		Summary: "software able to enumerate or decrypt stored credentials", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups: []Group{g("enumerate", "CredEnumerate", "CredRead", "VaultEnumerateItems", "LsaEnumerateLogonSessions"), g("decrypt", "CryptUnprotectData")},
		Need:   1, Complete: "moderate", Partial: "weak", Benign: "Browsers and credential-aware applications use CryptUnprotectData."},
	{ID: "cred.browser-data", Name: "Browser credential file references", Category: "credential access", Attack: []string{"T1555.003"},
		Summary: "software that names browser credential or cookie stores", Severity: models.SeverityMedium,
		Strings: []StrPattern{{"login data", "Chromium Login Data", "moderate"}, {"logins.json", "Firefox logins.json", "strong"}, {"key4.db", "Firefox key4.db", "strong"}, {"\\google\\chrome\\user data", "Chrome profile path", "moderate"}, {"cookies.sqlite", "Firefox cookies", "moderate"}},
		Benign:  "Browsers and migration tools."},
	{ID: "cred.shadow", Name: "Account database references", Category: "credential access", Attack: []string{"T1003.008"},
		Summary: "software that names the local account and password files", Severity: models.SeverityMedium, OS: []string{"elf", "macho"},
		Strings: []StrPattern{{"/etc/shadow", "/etc/shadow", "moderate"}, {"/etc/passwd", "/etc/passwd", "weak"}},
		Benign:  "Account management tools and libc name-service code."},
	{ID: "collect.keylog", Name: "Keyboard input capture", Category: "data collection", Attack: []string{"T1056.001"},
		Summary: "software able to hook or poll keyboard state", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups: []Group{g("hook or poll", "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "RegisterRawInputDevices"), g("read", "GetKeyState", "CallNextHookEx", "GetRawInputData", "MapVirtualKey", "GetForegroundWindow")},
		Need:   2, Complete: "moderate", Partial: "weak", Benign: "Hotkey tools, games and accessibility software."},

	// ---- file manipulation
	{ID: "file.bulk-modify", Name: "Directory traversal with file rewrite", Category: "file manipulation", Attack: []string{"T1083"},
		Summary: "software able to enumerate directories and rewrite or remove files", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("enumerate", "FindFirstFile", "FindFirstFileEx", "FindNextFile"), g("write", "WriteFile", "CreateFile"), g("replace or remove", "MoveFile", "MoveFileEx", "DeleteFile", "SetEndOfFile")},
		Complete: "weak", Benign: "Backup, sync, archive and antivirus tools do exactly this."},
	{ID: "file.inhibit-recovery", Name: "Backup and shadow copy removal commands", Category: "file manipulation", Attack: []string{"T1490"},
		Summary: "software that carries commands for deleting recovery data", Severity: models.SeverityHigh,
		Strings: []StrPattern{{"vssadmin delete shadows", "vssadmin delete shadows", "strong"}, {"vssadmin.exe delete shadows", "vssadmin.exe delete shadows", "strong"}, {"wmic shadowcopy delete", "wmic shadowcopy delete", "strong"}, {"bcdedit /set {default} recoveryenabled no", "bcdedit recovery off", "strong"}, {"wbadmin delete", "wbadmin delete", "strong"}},
		Benign:  "Backup management tools; the exact commands above are rarely benign."},
	{ID: "file.clear-logs", Name: "Event log clearing", Category: "file manipulation", Attack: []string{"T1070.001"},
		Summary: "software able to clear Windows event logs", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:  []Group{g("clear", "ClearEventLog", "EvtClearLog")},
		Strings: []StrPattern{{"wevtutil cl", "wevtutil cl", "moderate"}},
		Need:    1, Complete: "moderate", Benign: "System administration tools."},

	// ---- encryption
	{ID: "crypto.windows-api", Name: "Windows cryptography APIs", Category: "encryption", Attack: nil,
		Summary: "software able to encrypt or hash data through the Windows crypto stack", Severity: models.SeverityInfo, OS: []string{"pe"},
		Groups:   []Group{g("provider and keys", "CryptAcquireContext", "CryptGenKey", "CryptDeriveKey", "CryptImportKey", "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey", "BCryptImportKey"), g("operate", "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt")},
		Complete: "moderate", Benign: "TLS, DRM, password handling and file formats use these."},
	{ID: "crypto.constants", Name: "Cryptographic algorithm implementations", Category: "encryption", Attack: nil,
		Summary: "code containing the lookup tables or constants of well-known ciphers and hashes", Severity: models.SeverityInfo,
		Bytes: []BytePattern{
			{[]byte{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, "AES S-box", "strong"},
			{[]byte{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38}, "AES inverse S-box", "strong"},
			{[]byte{0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71}, "SHA-256 round constants", "strong"},
			{[]byte{0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8}, "MD5 sine table", "strong"},
			{[]byte("expand 32-byte k"), "ChaCha20/Salsa20 constant", "strong"},
			{[]byte{0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee}, "CRC-32 table", "moderate"},
			{[]byte{0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85}, "Blowfish initial P-array", "strong"},
		}, Benign: "Statically linked TLS and crypto libraries carry these tables whether or not a program uses them."},

	// ---- anti-analysis
	{ID: "evasion.debugger", Name: "Debugger detection", Category: "anti-debugging", Attack: []string{"T1622"},
		Summary: "software able to check whether it is being debugged", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups:   []Group{g("check", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread", "OutputDebugString", "DebugBreak")},
		Complete: "weak", Benign: "The Microsoft C runtime imports IsDebuggerPresent in ordinary programs."},
	{ID: "evasion.debugger.strong", Name: "Multiple debugger checks", Category: "anti-debugging", Attack: []string{"T1622"},
		Summary: "several independent ways of detecting a debugger", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups: []Group{g("presence", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"), g("process information", "NtQueryInformationProcess"), g("thread hiding", "NtSetInformationThread", "ZwSetInformationThread"), g("timing", "GetTickCount", "QueryPerformanceCounter", "GetSystemTimeAsFileTime")},
		Need:   3, Complete: "moderate", Partial: "weak", Benign: "Software protection and DRM."},
	{ID: "evasion.debugger.ptrace", Name: "Self-tracing", Category: "anti-debugging", Attack: []string{"T1622"},
		Summary: "software that can trace itself, a common way to block debuggers", Severity: models.SeverityLow, OS: []string{"elf", "macho"},
		Groups: []Group{g("trace", "ptrace")}, Complete: "weak", Benign: "Debuggers and profilers also import ptrace."},
	{ID: "evasion.vm", Name: "Virtualisation and sandbox detection strings", Category: "anti-virtualisation", Attack: []string{"T1497.001"},
		Summary: "software that carries names of virtual machine drivers, services or hardware", Severity: models.SeverityMedium,
		Groups:  []Group{g("firmware tables", "GetSystemFirmwareTable", "EnumSystemFirmwareTables")},
		Strings: []StrPattern{{"vboxservice", "VBoxService", "moderate"}, {"vboxguest", "VBoxGuest", "moderate"}, {"vmtoolsd", "vmtoolsd", "moderate"}, {"vmware virtual", "VMware hardware id", "moderate"}, {"qemu", "QEMU", "weak"}, {"sbiedll.dll", "Sandboxie", "moderate"}, {"\\\\.\\vboxminirdrdn", "VirtualBox device", "strong"}, {"prl_cc", "Parallels", "weak"}},
		Need:    1, Complete: "weak", Benign: "Virtualisation-aware installers, hypervisor tools and emulators."},

	// ---- discovery
	{ID: "discover.system", Name: "System information discovery", Category: "discovery", Attack: []string{"T1082"},
		Summary: "software able to read host name, OS version and hardware details", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("host", "GetComputerName", "GetComputerNameEx", "GetSystemInfo", "GetNativeSystemInfo"), g("version", "GetVersionEx", "RtlGetVersion", "VerifyVersionInfo"), g("memory and disk", "GlobalMemoryStatusEx", "GetDiskFreeSpaceEx", "GetLogicalDrives", "GetVolumeInformation")},
		Need:   2, Complete: "weak", Partial: "weak", Benign: "Installers, diagnostics and licensing checks."},
	{ID: "discover.user", Name: "User and domain discovery", Category: "discovery", Attack: []string{"T1033"},
		Summary: "software able to read the current user and domain membership", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("user", "GetUserName", "GetUserNameEx"), g("domain", "NetGetJoinInformation", "DsGetDcName", "NetWkstaGetInfo", "NetUserEnum", "NetUserGetInfo")},
		Need:   2, Complete: "moderate", Partial: "weak", Benign: "Enterprise software."},
	{ID: "discover.process", Name: "Process enumeration", Category: "discovery", Attack: []string{"T1057"},
		Summary: "software able to list running processes", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("snapshot", "CreateToolhelp32Snapshot", "EnumProcesses", "NtQuerySystemInformation"), g("iterate", "Process32First", "Process32Next", "EnumProcessModules")},
		Need:   2, Complete: "weak", Partial: "weak", Benign: "Task managers, installers checking for running copies, security tools."},
	{ID: "discover.network", Name: "Network configuration discovery", Category: "discovery", Attack: []string{"T1016", "T1135"},
		Summary: "software able to read adapter, address and share information", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("adapters", "GetAdaptersInfo", "GetAdaptersAddresses", "GetIpAddrTable", "GetBestRoute"), g("shares and neighbours", "NetShareEnum", "WNetOpenEnum", "WNetEnumResource", "GetIpNetTable")},
		Need:   1, Complete: "weak", Partial: "weak", Benign: "Network utilities and installers."},
	{ID: "discover.posix", Name: "Host and user discovery", Category: "discovery", Attack: []string{"T1082", "T1033"},
		Summary: "software able to read host name, kernel and user details", Severity: models.SeverityLow, OS: []string{"elf", "macho"},
		Groups: []Group{g("host", "uname", "gethostname", "sysinfo"), g("user", "getpwuid", "getpwnam", "getlogin", "getuid")},
		Need:   2, Complete: "weak", Partial: "weak", Benign: "Ubiquitous in system utilities."},

	// ---- collection
	{ID: "collect.screen", Name: "Screen capture", Category: "data collection", Attack: []string{"T1113"},
		Summary: "software able to copy screen contents", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:   []Group{g("device context", "GetDC", "GetWindowDC", "CreateDC"), g("copy", "BitBlt", "StretchBlt", "PrintWindow"), g("bitmap", "CreateCompatibleDC", "CreateCompatibleBitmap", "GetDIBits")},
		Complete: "moderate", Benign: "Remote-desktop, screenshot and screen-recording tools."},
	{ID: "collect.clipboard", Name: "Clipboard access", Category: "data collection", Attack: []string{"T1115"},
		Summary: "software able to read clipboard contents", Severity: models.SeverityLow, OS: []string{"pe"},
		Groups: []Group{g("open", "OpenClipboard"), g("read", "GetClipboardData")}, Complete: "moderate", Benign: "Editors and password managers."},
	{ID: "collect.audio", Name: "Audio capture", Category: "data collection", Attack: []string{"T1123"},
		Summary: "software able to record from audio input devices", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups: []Group{g("open input", "waveInOpen", "mciSendString"), g("record", "waveInStart", "waveInAddBuffer")}, Complete: "moderate", Benign: "Voice and media software."},

	// ---- privilege
	{ID: "priv.token", Name: "Access token privilege changes", Category: "privilege escalation", Attack: []string{"T1134"},
		Summary: "software able to enable privileges on its own process token", Severity: models.SeverityMedium, OS: []string{"pe"},
		Groups:  []Group{g("token", "OpenProcessToken", "NtOpenProcessToken"), g("privilege", "AdjustTokenPrivileges", "NtAdjustPrivilegesToken"), g("lookup", "LookupPrivilegeValue")},
		Strings: []StrPattern{{"sedebugprivilege", "SeDebugPrivilege", "moderate"}},
		Need:    2, Complete: "moderate", Partial: "weak", Benign: "Installers and administration tools adjust privileges."},
}

// RulesFor returns the rules that apply to a format family.
func RulesFor(family string) []Rule {
	var out []Rule
	for _, r := range Rules {
		if len(r.OS) == 0 {
			out = append(out, r)
			continue
		}
		for _, o := range r.OS {
			if o == family {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
