# Nahamcon21 – Typewriter

* **Category:** forensics

## Challenge


```
A CONSTELLATIONS employee had his machine crash and he lost all his work. Thankfully IT managed to get a memory dump.

Can you recover his work?

Download the file below. Note, this is a large ~400MB file and may take some time to download.
```

> Provided by the challenge was a large ZIP file. After unzipping you are met with a large
> file called `image.bin`. As stated in the challenge brief, we can assume this is a
> memory dump. To analyze this dump I used the tool [volatility](https://github.com/volatilityfoundation/volatility)

## Solution

First of all we have to analyze the provided file to get the OS of the broken machine.

```
$ volatility -f image.bin imageinfo
```
The option **-f** specifies the file to use and **imageinfo** is the respective command of
volatility we want to use.

```
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/jast/Documents/CTFs/nahamcon21/5_forensics/typewriter/image.bin)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x8293bde8L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x80b97000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2021-02-21 16:25:49 UTC+0000
     Image local date and time : 2021-02-21 08:25:49 -0800

```

As we can see in the obtained result, the OS producing the memory dump was likley Windows
7 and we should use the volatility profile Win7SP1x86_23418. Now we can start analyzing
the memory of the dump.

First of all we want to see a list of processes that were running during the gerneration
of the dump file.

```
$ volatility --profile=Win7SP1x86_23418 -f image.bin pstree

Volatility Foundation Volatility Framework 2.6
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x85e0d7d0:csrss.exe                                 304    296      9    389 2021-02-22 01:24:16 UTC+0000
. 0x8635b430:conhost.exe                             2036    304      2     33 2021-02-21 16:24:22 UTC+0000
 0x8573a330:wininit.exe                               340    296      4     78 2021-02-22 01:24:17 UTC+0000
. 0x85fb2b90:services.exe                             436    340      7    217 2021-02-22 01:24:18 UTC+0000
.. 0x86220c68:vmicsvc.exe                            1408    436      6    108 2021-02-21 16:24:21 UTC+0000
.. 0x85f523d8:SearchIndexer.                         2468    436     12    596 2021-02-21 16:24:29 UTC+0000
.. 0x85f687d8:OSPPSVC.EXE                            2828    436      5    143 2021-02-21 16:24:40 UTC+0000
.. 0x8612e5e0:svchost.exe                             920    436     31    739 2021-02-21 16:24:21 UTC+0000
... 0x86267af8:taskeng.exe                           1584    920      5     82 2021-02-21 16:24:21 UTC+0000
.. 0x86224818:taskhost.exe                           1432    436     11    224 2021-02-21 16:24:21 UTC+0000
.. 0x86379a68:sppsvc.exe                             1052    436      6    145 2021-02-21 16:24:23 UTC+0000
.. 0x862e8af8:cygrunsrv.exe                          1740    436      6     99 2021-02-21 16:24:22 UTC+0000
... 0x86359180:cygrunsrv.exe                         2020   1740      0 ------ 2021-02-21 16:24:22 UTC+0000
.... 0x8636a030:sshd.exe                              196   2020      6    107 2021-02-21 16:24:22 UTC+0000
.. 0x85ed0d20:svchost.exe                             680    436      5    233 2021-02-21 16:24:20 UTC+0000
.. 0x8619ea40:spoolsv.exe                            1200    436     16    299 2021-02-21 16:24:21 UTC+0000
.. 0x8607d528:svchost.exe                             564    436     11    361 2021-02-22 01:24:19 UTC+0000
.. 0x86159a00:svchost.exe                            1080    436     15    339 2021-02-21 16:24:21 UTC+0000
.. 0x8637d030:svchost.exe                            1924    436      5     92 2021-02-21 16:24:23 UTC+0000
.. 0x86308030:wlms.exe                               1852    436      4     46 2021-02-21 16:24:22 UTC+0000
.. 0x860eebe8:svchost.exe                             844    436     20    431 2021-02-21 16:24:21 UTC+0000
... 0x862475f8:dwm.exe                               2200    844      5     75 2021-02-21 16:24:28 UTC+0000
.. 0x862334b8:vmicsvc.exe                            1460    436      3     67 2021-02-21 16:24:21 UTC+0000
.. 0x860ae470:svchost.exe                             728    436     16    339 2021-02-21 16:24:20 UTC+0000
.. 0x861b76d8:svchost.exe                            1244    436     19    308 2021-02-21 16:24:21 UTC+0000
.. 0x8621b6a8:vmicsvc.exe                            1384    436      6    105 2021-02-21 16:24:21 UTC+0000
.. 0x86249d20:vmicsvc.exe                            1520    436      5     81 2021-02-21 16:24:21 UTC+0000
.. 0x862675e0:vmicsvc.exe                            1576    436      5     82 2021-02-21 16:24:21 UTC+0000
.. 0x86091d20:VBoxService.ex                          628    436     11    116 2021-02-22 01:24:19 UTC+0000
.. 0x86127030:svchost.exe                             888    436     18    341 2021-02-21 16:24:21 UTC+0000
.. 0x86274030:svchost.exe                            1620    436     13    328 2021-02-21 16:24:21 UTC+0000
. 0x85fb68d0:lsass.exe                                452    340      8    572 2021-02-22 01:24:18 UTC+0000
. 0x85fb7c40:lsm.exe                                  460    340      9    148 2021-02-22 01:24:18 UTC+0000
 0x84841938:System                                      4      0     72    500 2021-02-22 01:24:16 UTC+0000
. 0x857a5d20:smss.exe                                 236      4      2     29 2021-02-22 01:24:16 UTC+0000
 0x85ed2d20:winlogon.exe                              392    332      5    116 2021-02-22 01:24:18 UTC+0000
 0x88187558:csrss.exe                                 352    332      8    204 2021-02-22 01:24:17 UTC+0000
 0x8623e030:explorer.exe                             2212   2192     29    628 2021-02-21 16:24:28 UTC+0000
. 0x85f3bd20:StikyNot.exe                            2320   2212      9    144 2021-02-21 16:24:29 UTC+0000
. 0x85f56a68:VBoxTray.exe                            2312   2212     13    159 2021-02-21 16:24:29 UTC+0000
. 0x85fa2d20:WINWORD.EXE                             2760   2212      8    316 2021-02-21 16:24:39 UTC+0000
```
As you can see by the command issued, we now have to specify the profile (**--profile=Win7SP1x86_23418**) so volatility can interpret the memory alignment correclty.
By using the **pstree** command, we get the above list of running processes and their
parent processes..
What immediatley stands out is one of the last processes running was **WINWORD.EXE** which
is, Microsoft Word, having the PID 2760. As this was one of the last processes running, the
probability of finding the flag there was pretty high. But as processes can hide
themselves while running, we issue another command to search for possibly hidden
processes.

```
$ volatility --profile=Win7SP1x86_23418 -f image.bin psxview

Volatility Foundation Volatility Framework 2.6
Offset(P)  Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
---------- -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x7e759a00 svchost.exe            1080 True   False  True     True   True  True    True     
0x7e9b7c40 lsm.exe                 460 True   False  True     True   True  True    False    
0x7e956a68 VBoxTray.exe           2312 True   False  True     True   True  True    True     
0x7e579a68 sppsvc.exe             1052 True   False  True     True   True  True    True     
0x7e9b2b90 services.exe            436 True   False  True     True   True  True    False    
0x7e7b76d8 svchost.exe            1244 True   False  True     True   True  True    True     
0x7e9687d8 OSPPSVC.EXE            2828 True   False  True     True   True  True    True     
0x7e424818 taskhost.exe           1432 True   False  True     True   True  True    True     
0x7e420c68 vmicsvc.exe            1408 True   False  True     True   True  True    True     
0x7e691d20 VBoxService.ex          628 True   False  True     True   True  True    True     
0x7e727030 svchost.exe             888 True   False  True     True   True  True    True     
0x7e508030 wlms.exe               1852 True   False  True     True   True  True    True     
0x7e67d528 svchost.exe             564 True   False  True     True   True  True    True     
0x7e449d20 vmicsvc.exe            1520 True   False  True     True   True  True    True     
0x7e474030 svchost.exe            1620 True   False  True     True   True  True    True     
0x7e8d2d20 winlogon.exe            392 True   False  True     True   True  True    True     
0x7e4334b8 vmicsvc.exe            1460 True   False  True     True   True  True    True     
0x7e43e030 explorer.exe           2212 True   False  True     True   True  True    True     
0x7f13a330 wininit.exe             340 True   False  True     True   True  True    True     
0x7e79ea40 spoolsv.exe            1200 True   False  True     True   True  True    True     
0x7e8d0d20 svchost.exe             680 True   False  True     True   True  True    True     
0x7e4475f8 dwm.exe                2200 True   False  True     True   True  True    True     
0x7e55b430 conhost.exe            2036 True   False  True     True   True  True    True     
0x7e57d030 svchost.exe            1924 True   False  True     True   True  True    True     
0x7e9b68d0 lsass.exe               452 True   False  True     True   True  True    False    
0x7e4e8af8 cygrunsrv.exe          1740 True   False  True     True   True  True    True     
0x7e9523d8 SearchIndexer.         2468 True   False  True     True   True  True    True     
0x7e93bd20 StikyNot.exe           2320 True   False  True     True   True  True    True     
0x7e72e5e0 svchost.exe             920 True   False  True     True   True  True    True     
0x7e6eebe8 svchost.exe             844 True   False  True     True   True  True    True     
0x7e56a030 sshd.exe                196 True   False  True     True   True  True    True     
0x7e6ae470 svchost.exe             728 True   False  True     True   True  True    True     
0x7e41b6a8 vmicsvc.exe            1384 True   False  True     True   True  True    True     
0x7e4675e0 vmicsvc.exe            1576 True   False  True     True   True  True    True     
0x7e9a2d20 WINWORD.EXE            2760 True   False  True     True   True  True    True     
0x7e467af8 taskeng.exe            1584 True   False  True     True   True  True    True     
0x7e559180 cygrunsrv.exe          2020 True   False  False    True   False True    False    2021-02-21 16:24:22 UTC+0000
0x7f1a5d20 smss.exe                236 True   False  True     True   False False   False    
0x7ffc0938 System                    4 True   False  True     True   False False   False    
0x7e80d7d0 csrss.exe               304 True   False  True     True   False True    True     
0x7c787558 csrss.exe               352 True   False  True     True   False True    True     
```

As you can see in the column **pslist**, all processes would show up using that command
and therefore also while using the **pstree** command. So there are no hidden processes, so lets
start investigating the MSWORD.EXE process. We do that by
using the command **procdump** and **memdump** and specifying the PID of the process to
dump, in our case **-p 2760**.


```
$ volatility --profile=Win7SP1x86_23418 -f image.bin procdump -p 2760 -D .

Volatility Foundation Volatility Framework 2.6
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x85fa2d20 0x2fa90000 WINWORD.EXE          OK: executable.2760.exe
```
**procdump** extracts the executable which probably wont help us, so we wouldn't really
need that step. The last argument (**-D .**) specifies the directory to dump in, by
providing the dot, we tell volatility to dump the files in the current directory.

```
$ volatility --profile=Win7SP1x86_23418 -f image.bin memdump -p 2760 -D .

Volatility Foundation Volatility Framework 2.6
************************************************************************
Writing WINWORD.EXE [  2760] to 2760.dmp
```
The command **memdump** however dumps the addressable memory of the process, so this is the
interesting file for us.

Now we can analyze the created .dmp file using the `strings` command. As this contains
the memory of the process, there is a lot of content and it is unlikley that we can
extract the flag from this file directly. Nevertheless I tried to extract a flag but as
expected nothing was found. 

```
$ strings 2760.dmp |grep flag{
```

What we are searching for is a filepath or something similar, so we can extract the file,
the user was writing in. To do that we grep for the file extension. As we know it is MS
Word we are analyzing, we yield the following:

```
$ strings 2760.dmp | grep .docx

C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
"C:\Program Files\Microsoft Office\Office14\WINWORD.EXE" /n "C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx"
C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
CONFIDENTIAL DOCUMENT.docx.LNK
C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
.docx
.docx
.docx
.docx4%
.docx
.docx
.docx
.docx
.docxml
.docx
.docx
.docx
CONFIDENTIAL DOCUMENT.docx
CONFIDENTIAL DOCUMENT.docx
.docx
CONFIDENTIAL DOCUMENT.docx.lnk
CONFIDENTIAL DOCUMENT.docx.lnk
CONFIDENTIAL DOCUMENT.docx.LNK=0
CONFIDENTIAL DOCUMENT.docx.LNK=0
CONFIDENTIAL DOCUMENT.docx.LNK=0
CONFIDENTIAL DOCUMENT.docx.LNK=0
```
This looks very promising. As we can see, the user worked on a document called
CONFIDENTIAL DOCUMENT.docx. Lets try to get this file. To do this, we have to find the
memory address of the file. We can use the volatility command **filescan** to scan all the
files. As we just want to see the result for our file, we filter the output.

```
$ volatility --profile=Win7SP1x86_23418 -f image.bin filescan |grep CONFIDENTIAL

Volatility Foundation Volatility Framework 2.6
0x000000007e841f80      8      0 RW-r-- \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
0x000000007eb665b8      2      1 RW-r-- \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
```
Now we have the memory Adress of the file. We can retrieve the file using **dumpfiles**

```
$ mkdir filedump
$ volatility --profile=Win7SP1x86_23418 -f image.bin dumpfiles -Q 0x000000007e841f80 -n -u -D filedump

Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7e841f80   None   \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
SharedCacheMap 0x7e841f80   None   \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
```
Using `mkdir` we can create a new directory for better structure. The **dumpfiles**
command needs a few options to yield the desired result. Using **-Q 0x000000007e841f80**
we specify the physical address so volatility dumps the correct files. With the option **-n** the extracted file name is included in the output path,
**-u** relaxes some safety constraints to extract more data and finally **-D** specifies
the dump directory we just created.

So now we have two dumped files, the one which interests us is the bigger .vcab file. So
using
```
$ cp file.None.0x85e41b30.CONFIDENTIAL\ DOCUMENT.docx.vacb confidential.zip 
```
We can create a zip file which we can extract. But apparently it's corrupted.

```
$ unzip confidential.zip

Archive:  confidential.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
unzip:  cannot find zipfile directory in one of confidential.zip or
        confidential.zip.zip, and cannot find confidential.zip.ZIP, period.
```
So lets try to fix it with zip. With zip we can fix files using the **-FF** option.

```
$ zip -FF confidential.zip --out file.zip 
```

So now we can create a new subsdirectory to maintain a clean workspace and unzip the file.

```
$ mkdir zip
$ unzip file.zip -d zip
```

The file that interests us now is `word/document.xml`

So we open the file in sublime text and are met with this:

![Screenshot of sublime](https://github.com/Jast38/CTFWriteups/blob/main/Nahamcon21/Typewriter/assets/SublimeInitial.png?raw=true)

To nicen this we can use a Sublime Addon called Indent XML and after using that, we end up
with a much more readable file (the screenshot only shows a part of the file, as it was
pretty long):

![Screenshot of readable file](https://github.com/Jast38/CTFWriteups/blob/main/Nahamcon21/Typewriter/assets/SublimeReadable.png)

Bingo. So here we have our flag, each character contained in `<w:t>f</w:t>`, one per line.
Using Sublimes Find and Replace function we can select all those parts of our flag using
the RegEx `<w:t>.</w:t>` (which matches everything that is surrounded by `<w:t>` and `</w:t>`), mark them and cut them out to delete the remaining lines and
paste them back in again (just because I was apparently to dumb to figure out the RegEx to
mark all but the pattern).

![Screenshot of readable file](https://github.com/Jast38/CTFWriteups/blob/main/Nahamcon21/Typewriter/assets/SublimeFlag.png)

To extract the flag we can use a RegEx once again. We search for `<w:t>|</w:t>|\n`, which
matches every tag and newline character, and
replace them with an empty string and there we have our flag.
```
flag{c442f9ee67c7ab471bb5643a9346cf5e}
```

In conclusion was this a very nice forensic challenge and I learned a lot on the way.
