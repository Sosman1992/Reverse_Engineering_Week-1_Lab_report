# Week 1 - Simple Static Analysis

The Weeks Lab was focus on the use of file hashes as technique for identifying malware samples. Additionally, submitting sample of malware files or hashes Google's VirusTotal tool to view the outcomes of a scan with a variety of antivirus programs was performed. Furthermore how to use `strings` to search for ASCII and Unicode strings inside of a binary was also learnt and also discovered how to use PEiD to determine whether a binary of a malware samples executable or linked library file is compressed to conceal its contents. Lastly exploration of Windows system tools that are used by portable executable including libraries that get dynamically linked and which functions are imported was also learnt.

---
# Lab 1-1 

## Executive Summary

These files appear to be malware, and they appear to engage in some kind of filesystem manipulation. We have so far not found what they do, but there are indications that it hides a `kerne1.dll` file in the `system32` directory.

## Indicators of Compromise 

**Compilation Date (presumed):** DEC 2010

**MD5 Hash (EXE):** bb7425b82141a1c0f7d60e5106676bb1 

**MD5 Hash (DLL):** 290934c61de9176ad682ffdd65f0a669  

**File to look for:** `C:\windows\system32\kerne132.dll`

## Mitigations

- Delete files that match this file's hash! 
- Scan Windows machines for `system32\kerne132.dll`

## Evidence

This malware consisted of two components, a portable executable (EXE) and a dynamically linked library (DLL). Submitting either to VirusTotal sets off dozens of vendors' virus classifiers.

Using `strings` on the `.EXE`, we find the message string "`WARNING_THIS_WILL_DESTROY_YOUR_MACHINE`", and some references to several file manipulation functions. We also see the suspicious string "`C:\windows\system32\kerne132.dll`", which replaces the `l` in kernel with a `1`. Such a file is not present in Windows by default, so it's presence could be an indicator of compromise.

Using `strings` on the `.DLL` did not yield anything useful.

Opening these files with PEview, we see that they both claim to have been compiled in late 2010. This matches what VirusTotal reported, but VirusTotal only saw samples appear in mid-2012.

Using DependencyWalker on the `.EXE`, we can see which functions are imported from various other DLLs. Two of these which are particularly notable are `CreateProcess` and `Sleep`. The `Practical Malware Analysis` textbook teaches us that these functions can be combined to create a backdoor for running this malware. *(You would really only find this if you read the solutions at the back of the book, which is fair game.)*

---
# Lab 1-2

## Executive Summary
The sample appear to be malware, and it seems it will be running a service named `MalService` on the infected machine that enables in connecting to a website `www.malwareanalysis.com` to download other malwares

## Indicators of Compromise

*Compilation Date (presumed):** JANUARY 2011

**MD5 Hash (EXE):** 8363436878404da0ae3e46991e355b83 

**IP:** 

**URLs:** http://www.malwareanalysisbook.com/

**Registry Keys:*

**Mutex:**

**File names:** MalService


## Mitigations
- Checking on machines to see if they are running a service called `MalService` then it implies the machine is infected

## Evidence

Opening the Lab file with PEiD, it can be seen that the file is packed with UPX a packing utililty. Using an unpacker it was able to unpack the file and get it to be recognized as Microsoft visual file.

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, `InternetOpenUrlA` and `InternetOpenA`.


Using strings in the unpacked`.EXE`, suggests that infected machines will connect to `http://www.malwareanalysis.com` and in addition a running service named `MalService`

---
# Lab 1-3

## Executive Summary
## Indicators of Compromise
## Mitigations
## Evidence

---
# Lab 1-4

## Executive Summary
## Indicators of Compromise
## Mitigations
## Evidence

## Tools used and their functions
- PeID : For confirming whether a file is packed or obfuscated
- Strings: A sysinternals program that shows the strings in a program
- PEView: Shows useful summary information about the portable executable(s), including compile time and imports
- Dependency Walker: For showing imports
_ Resource Hacker: Allows for viewing of objects in the resource section of the portable executable, and also enabling to extract data from the portable executable.
