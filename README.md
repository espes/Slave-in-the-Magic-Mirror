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
- A copy of the `airtunesd` binary from AppleTV firmware for AppleTV2,1 build 9A334v. Either extract it yourself, or run `get_airtunesd.py`:

```
pypy -m pip install beautifulsoup4 construct cryptography requests

pypy get_airtunesd.py
```


Then you're ready to run *Slave in the Magic Mirror*!

```
pypy -m pip install biplist construct cryptography macholib zeroconf

pypy airplay.py
```

Start AirPlay on your device and hopefully you'll get something like this:

![screenshot](https://i.imgur.com/w5hEgsT.png)


Known Issues
------------

- Audio doesn't work
 - No media software correctly supports the audio format (AAC-ELD with short frames in LATM in MPEG-TS) despite it all being to-spec -_- FFmpeg/libav is being fixed, so support will reach VLC 'soon'.
- Rotating the device and launching some games crashes VLC
 - This is fixed in VLC 2.2
- I've only tested it with iOS 7.1.2


Code Overview
-------------

`airplay.py` - Main implementation of the AirPlay protocol

`arm/` - Simple ARMv7 interpreter based on [arm-js](https://github.com/ozaki-r/arm-js)

`drm.py` - Implementation of FairPlay SAP by calling into airtunesd

`loader.py` `dyld_info.py` - Mach-O loader and minimal HLE for iOS binaries

`aac.py` `mp4.py` `mpegts.py` - Implementations of bits of ISO/IEC 14496 Part 3, 10 and ISO/IEC 13818 Part 1. Enough to dump the AirPlay packets into a useful container.

`get_airtunesd.py` - A script to download and extract airtunesd from an Apple TV firmware update. Includes minimal implementations of the FileVault and DMG file formats.

`hfs/` - For `get_airtunesd.py`. Simple implementation of the HFS filesystem adapted from [iphone-dataprotection](https://code.google.com/p/iphone-dataprotection/)
