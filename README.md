# Week 1 - Simple Static Analysis

The Weeks Lab was focus on the use of file hashes as technique for identifying malware samples. Additionally, submitting sample of malware files or hashes Google's VirusTotal tool to view the outcomes of a scan with a variety of antivirus programs was performed. Furthermore how to use `strings` to search for ASCII and Unicode strings inside of a binary was also learnt and also discovered how to use PEiD to determine whether a binary of a malware samples executable or linked library file is compressed to conceal its contents. Lastly exploration of Windows system tools that are used by portable executable including libraries that get dynamically linked and which functions are imported was also learnt.

---
# Lab 1-1 

## Executive Summary

These files were both compiled on the same date within a of each other, looking at the `time date stamp` it can be concluded that they are part of the same package, and they appear to engage in some kind of filesystem manipulation. However, both the `.exe` and `.dll` are neither packed or obfuscated and in addition to the static analysis conducted so far on thes samples using the available tools I am unable to conclude on the detriment or infections they are or would cause to systems they will infect, but there are indications that they are disguising to be a Windows  kernel.dll file in the `system32` directory of the computer they will infect but analysing statically it is a modified `kerne1.dll` naming not the usual Windows file .

## Indicators of Compromise 

**Compilation Date (presumed):** DEC 2010

**MD5 Hash (EXE):** bb7425b82141a1c0f7d60e5106676bb1

**SHA-1 Hash (EXE):**  9dce39ac1bd36d877fdb0025ee88fdaff0627cdb 

**SHA-256 Hash (EXE):**  58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47 

**MD5 Hash (DLL):** 290934c61de9176ad682ffdd65f0a669 

**SHA-1 Hash (DLL):**  a4b35de71ca20fe776dc72d12fb2886736f43c22 

**SHA-256 Hash (DLL):** f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba

**File to look for:** `C:\windows\system32\kerne132.dll`

**File type:** Win32 DLL 

**PEiD packer:** Microsoft Visual C++ v6.0 DLL 



## Mitigations

- Deletions of files matching any of these hashes obtained from the scanning result 
- Scan Windows machines for `system32\kerne132.dll`

## Evidence

These malware are made up of two components, a portable executable (EXE) and a dynamically linked library (DLL). Uploading either to VirusTotal sets off dozens of vendors' virus classifiers.

Opening these files with PEiD indicates that these files were written and compiled using Microsoft Visual C++ 6.0 , we see that they both claim to have been compiled in late 2010. 

Opening the `.EXE` in BinText, the message string "`WARNING_THIS_WILL_DESTROY_YOUR_MACHINE`", and some other suspicious string "`C:\windows\system32\kerne132.dll`", which replaces the `l` in kernel with a `1`. Nonetheless, windows does not have a file named `kerne132.dll` hence the presence of such serves to be a proof that of malware availability.

Opening these files with PEview, we see that they both claim to have been compiled in late 2010. This matches what VirusTotal reported, but VirusTotal only saw samples appear in mid-2012.

Using DependencyWalker on the `.EXE`, revealed the functions that were  imported from various other DLLs. 

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

Opening the Lab file with PEiD, it can be seen that the file is packed with UPX a packing utililty. Using an unpacker it was able to unpack the file and get it to be recognized as Microsoft visual file. that was written and compiled using Microsoft Visual C++ 6.0

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, `InternetOpenUrlA` and `InternetOpenA`.


Using strings in the unpacked`.EXE`, suggests that infected machines will connect to `http://www.malwareanalysis.com` and in addition a running service named `MalService`

---

## Tools used and their functions
- PeID : For confirming whether a file is packed or obfuscated
- BinText: A sysinternals GUI program that shows the strings in a program
- PEView: Shows useful summary information about the portable executable(s), including compile time and imports
- Dependency Walker: For showing imports

