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
> memory dump. To analyse this dump I used the tool [volatility](https://github.com/volatilityfoundation/volatility)

## Solution

First of all we have to analyse the provided file to get the OS of the broken machine.

```
$volatility -f image.bin imageinfo
```
The option **-f** specifies the file to use and **imageinfo** is the respective plugin of
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

```
The flag.
```
