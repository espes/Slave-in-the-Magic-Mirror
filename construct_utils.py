# construct_utils.py
#
# Copyright 2015, espes
#
# Licensed under GPL Version 2 or later
#

from construct import *

# This file goes to fairly extreme lengths to work around inadequacies of construct.
# I've been planning on replacing construct because NIH, but this'll do for now...

class Bork(Construct):
    def __init__(self, msg=None):
        Construct.__init__(self, None)
        self.msg = msg
    def _parse(self, stream, context):
        raise Exception, self.msg
    def _build(self, obj, stream, context):
        raise Exception, self.msg
    def _sizeof(self, context):
        raise Exception, self.msg


class ParseOnly(Subconstruct):
    def _build(self, obj, stream, context):
        pass

class BuildOnly(Subconstruct):
    def _parse(self, stream, context):
        if self.name in context:
            return context[self.name]
        return None

class Hash(Subconstruct):
    def __init__(self, subcon, startfunc, lengthfunc, hashfunc):
        Subconstruct.__init__(self, subcon)
        self.startfunc = startfunc
        self.lengthfunc = lengthfunc
        self.hashfunc = hashfunc
    def _parse(self, stream, context):
        newpos = self.startfunc(context)
        origpos = stream.tell()
        stream.seek(newpos, 0)
        data = stream.read(self.lengthfunc(context))
        stream.seek(origpos, 0)

        readhash = self.subcon._parse(stream, context)
        calchash = self.hashfunc(data, context)
        assert readhash == calchash
        return readhash
    def _build(self, obj, stream, context):
        newpos = self.startfunc(context)
        origpos = stream.tell()
        stream.seek(newpos, 0)
        data = stream.read(self.lengthfunc(context))
        stream.seek(origpos, 0)

        calchash = self.hashfunc(data, context)
        self.subcon._build(calchash, stream, context)


def UBInt24(name):
    # return EmbeddedBitStruct(Bits(name, 24))
    return ExprAdapter(Array(3, UBInt8(name)),
        decoder=lambda obj, ctx: (obj[0] << 16) | (obj[1] << 8) | obj[2],
        encoder=lambda obj, ctx:
            [(obj >> 16) & 0xff, (obj >> 8) & 0xff, obj & 0xff],
        )



class DefaultingContainer(Container):
    def __getattr__(self, name):
        try:
            return Container.__getattr__(self, name)
        except AttributeError:
            return None

# Can't use Aligned because BitStreamReader can't seek -_-
class ByteAlign(Construct):
    def __init__(self):
        Construct.__init__(self, None)
    def _parse(self, stream, context):
        while stream.total_size % 8:
            stream.read(1)
    def _build(self, obj, stream, context):
        while sum(map(len, stream.buffer)) % 8:
            stream.write("\x00")

class FixedLengthReader(object):
    def __init__(self, substream, length):
        self.substream = substream
        self.length = length
        self.startpos = self.tell()
        self.endpos = self.startpos+length
    def close(self):
        self.substream.seek(self.endpos, 0)
    def tell(self):
        return self.substream.tell()
    def seek(self, pos, whence=0):
        r = self.substream.seek(pos, whence)
        if not self.startpos<=self.tell()<=self.endpos:
            raise ValueError("seek outside range?")
    def read(self, count):
        count = max(0, min(count, self.endpos-self.tell()))
        return self.substream.read(count)

class Restream2(Subconstruct):
    def __init__(self, subcon, reader=None, writer=None):
        Subconstruct.__init__(self, subcon)
        self.reader = reader
        self.writer = writer
    def _parse(self, stream, context):
        if self.reader:
            stream2 = self.reader(stream, context)
            obj = self.subcon._parse(stream2, context)
            stream2.close()
        else:
            obj = self.subcon._parse(stream, context)
        return obj
    def _build(self, obj, stream, context):
        if self.writer:
            stream2 = self.writer(stream, context)
            self.subcon._build(obj, stream2, context)
            stream2.close()
        else:
            self.subcon._build(obj, stream, context)
    def _sizeof(self, context):
        raise NotImplementedError


def container_add(d, **kv):
    c = d.copy()
    c.update(kv)
    return c

class StructLengthAdapter(Adapter):
    def __init__(self, subcon, encoder, decoder):
        Adapter.__init__(self, subcon)
        self.length_encoder = encoder
        self.length_decoder = decoder
    def _decode(self, obj, context):
        context._struct_length = self.length_decoder(obj, context)
        return obj
    def _encode(self, obj, context):
        return self.length_encoder(context._struct_length, obj, context)


def StructWithLengthAdapter(name, lengthcon, *datacon, **kw):
    inclusive = kw.pop("inclusive", False)
    return Struct(name,
        Anchor("_startpos"),
        BuildOnly(Value("_struct_length", lambda ctx: 0)),
        lengthcon,
        Anchor("_lengthpos"),
        Restream2(
            Embed(Struct(None, *datacon)),
            reader = lambda stream, ctx: FixedLengthReader(stream,
                ctx._struct_length-lengthcon._sizeof(ctx) if inclusive
                else ctx._struct_length)
        ),
        Anchor("_endpos"),

        BuildOnly(Value("_struct_length",
            lambda ctx: ctx._endpos-ctx._startpos if inclusive else ctx._endpos-ctx._lengthpos)),
        BuildOnly(Pointer(this._startpos, lengthcon)),
        allow_overwrite=True
    )

def StructWithLength(name, lengthcon, *datacon, **kv):
    return StructWithLengthAdapter(name,
        StructLengthAdapter(
            lengthcon,
            encoder = lambda length, obj, con: length,
            decoder = lambda obj, con: obj),
        *datacon,
        **kv)


# def P(name=None):
#     return Probe(name, show_stream=False, show_stack=False)


if __name__ == "__main__":
    ts = Struct("tmp",
        UBInt8("a"),
        UBInt8("b"),
        StructWithLengthInStruct("tmpq",
            StructLengthAdapter(
                Embed(Struct("tmp2",
                    UBInt8("c"),
                    UBInt8("lollength"),
                    UBInt8("e"),
                    P("tmp2")
                )),
                encoder = lambda length, obj, ctx: container_add(obj, lollength=length),
                decoder = lambda obj, ctx: obj.lollength
            ),
            Embed(Struct("tmp3",
                UBInt8("d"),
                P("tmp3")
            ))
        )
    )

    tss = "abc\x01ed"
    print ts.parse(tss)

    tc = Container(
        a = 97,
        b = 98,
        tmpq = DefaultingContainer(
            # lollength = 1,
            c = 99,
            e = 101,
            d = 100))
    print `ts.build(tc)`
