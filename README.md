juiced - The latest version is v1.7

Ruby script that places output based around Matthew Graebers PowerShell Attacks (epic post) and TrustedSec's modifcations into a variety of payload formats.


Tool Functionality:
This script will take in a Msfvenom formatted payload (ie.windows/meterpreter/reverse_https) with appropriate options and issue it to msfvenom, modify the received shellcode, and embed it within the specified payload type.

Current Payload Formats:
macro = Spits out a fully functional copy/pasta word macro
jar = A executable jar file that will issue the powershell syntax*
vbs = A executable vbs file that will issue the powershell syntax*
js = A executable js file that will issue the powershell syntax*
ps = The actual copy/pastable command you can paste into a command prompt
war = A war file that will issue the powershell syntax*
asp = A asp file that will issue the powershell syntax*
*These payload types will require a filename to be given.

As I find more fun ways of executing commands with different extensions I will add them in.

Tool Usage:
	ruby juiced.rb MsfvenomPayload Lhost Lport payloadFlag PayloadName

	Note: Payload name required for jar file, and is not required for other payloads."
	Payload Options: jar, ps, macro, vbs, and js.
======
