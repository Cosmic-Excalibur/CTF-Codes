from math import ceil

red      = ( 255,   0,   0)
yellow   = ( 255, 255,   0)
blue     = (   0,   0, 255)
magenta  = ( 255,   0, 255)

bytes_to_printable_string = lambda s: ''.join(chr(x) if x in range(32, 127) else '\x1b[31;1m·\x1b[0m' for x in s)

def colorify(text, start = blue, end = magenta):
    gradient = lambda i, l: tuple(int(s + (e - s) * i / l) for s, e in zip(start, end))
    l = max(len(t) for t in text.split("\n"))
    ret = []
    for line in text.split("\n"):
        t = ''.join("\x1b[38;2;%s;%s;%s;1m%s"%(gradient(i, l) + (a,)) for i, a in enumerate(line))
        ret.append(t + '\x1b[0m')
    return '\n'.join(ret)