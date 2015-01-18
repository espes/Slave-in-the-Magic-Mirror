Slave in the Magic Mirror
=========================

What?
-----

In short: Apple has a thing that lets you show what's on your iPhone or iPad or Mac on your Apple TV. This lets you see it on your Linux or Mac computer or media center too, maybe.

This is an open-source implementation of [Apple AirPlay Mirroring](https://en.wikipedia.org/wiki/AirPlay#AirPlay_Mirroring)

AirPlay Mirroring uses a funky mish-mash of standards wrapped in some DRM. *Slave in the Magic Mirror* packs the audio and video data into a standard media container and hands it to VLC. The DRM is handled by calling into the original Apple TV server binary using a pure-python ARM interpreter.

It's not exactly production-ready, but try it out!

How?
----

You need:

- [VLC](https://www.videolan.org/vlc/)
- [PyPy](http://pypy.org/) with [pip](https://en.wikipedia.org/wiki/Pip_%28package_manager%29)
- A copy of the `airtunesd` binary from AppleTV firmware for AppleTV2,1 build 9A334v. Put it in this directory.

Then:

```
pypy -m pip install biplist construct cryptography macholib zeroconf

pypy airplay.py
```

![screenshot](https://i.imgur.com/w5hEgsT.png)


Known Issues
------------

- Audio doesn't work
 - The audio is packed into the MPEG-TS stream (mostly?) to-spec. The problem is no player correctly supports AAC-ELD and LATM...
- Rotating the device and launching some games crashes VLC
 - lol
- I've only tested it with iOS 7.1.2


Code Overview
-------------

`airplay.py` - Main implementation of the AirPlay protocol

`arm/` - Simple ARMv7 interpreter based on [arm-js](https://github.com/ozaki-r/arm-js)

`drm.py` - Implementation of FairPlay SAP by calling into airtunesd

`loader.py` `dyld_info.py` - Mach-O loader and minimal HLE for iOS binaries

`aac.py` `mp4.py` `mpegts.py` - Implementations of bits of ISO/IEC 14496 Part 3, 10 and ISO/IEC 13818 Part 1. Enough to dump the AirPlay packets into a useful container.
