# thread-hijacking-in-csharp
Performs thread hijacking of a process thread to execute malicious code, then resumes where the thread left off

## Setup
Replace the "SHELLCODE_HERE" variable in t_hijack.cs with shellcode that has been crypted through crypt.cs, then compile t_hijack.cs into a DLL.

In the load.ps1 Powershell script replace 'localhost' with the webserver of your choosing. This webserver will host the compiled thread hijacking DLL. Running load.ps1 will load and execute the thread hijacking DLL through reflection.
