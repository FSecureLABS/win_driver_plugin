# Device name finding functions.
# A bulk of this is taken from https://github.com/fireeye/flare-floss
import mmap
import re
import collections
import idc

ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
SLICE_SIZE = 4096

String = collections.namedtuple("String", ["s", "offset"])


def buf_filled_with(buf, character):
    dupe_chunk = character * SLICE_SIZE
    for offset in xrange(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset: offset + SLICE_SIZE]
        if dupe_chunk[:len(new_chunk)] != new_chunk:
            return False
    return True


# Extract naive UTF-16 strings from the given binary data.
def extract_unicode_strings(buf, n=4):

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def get_unicode_device_names():
    path = idc.GetInputFile()
    min_length = 4
    possible_names = set()
    with open(path, "rb") as f:
        b = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for s in extract_unicode_strings(b, n=min_length):
            if str(s.s).startswith('\\Device\\'):
                possible_names.add(str(s.s))
    return possible_names


def find_unicode_device_name():
    possible_names = get_unicode_device_names()
    if len(possible_names) == 1:
        if possible_names.pop() == '\\Device\\':
            print "The Device prefix was found but no full device paths, the device name is likely obsfucated or created on the stack."
            return False
    elif len(possible_names) > 1:
        print "Possible devices names found:"
        for i in possible_names:
            print "\t" + i
        return True
    else:
        print "No potential device names found - it may be obsfucated or created on the stack in some way."
        return False


def search():
    if not find_unicode_device_name():
        print "Unicode device name not found, attempting to find obsfucated and stack based strings."
        try:
            import floss
            import floss.identification_manager
            import floss.main
            import floss.stackstrings
            import viv_utils
        except:
            print "Please install FLOSS to continue, see: https://github.com/fireeye/flare-floss/"

        sample_file_path = idc.GetInputFile()

        try:
            vw = viv_utils.getWorkspace(sample_file_path, should_save=False)
        except Exception, e:
            print("Vivisect failed to load the input file: {0}".format(e.message))
            return

        functions = set(vw.getFunctions())
        plugins = floss.main.get_all_plugins()
        device_names = set()

        stack_strings = floss.stackstrings.extract_stackstrings(vw, functions)
        for i in stack_strings:
            device_names.add(i)
        dec_func_candidates = floss.identification_manager.identify_decoding_functions(vw, plugins, functions)
        func_index = viv_utils.InstructionFunctionIndex(vw)
        decoded_strings = floss.main.decode_strings(vw, func_index, dec_func_candidates)
        if len(decoded_strings) > 0:
            for i in decoded_strings:
                device_names.add(str(i.s))
            print "Potential devices names from obsfucated or stack strings:"
            for i in device_names:
                if i.startswith('\\Device\\'):
                    print i
                else:
                    print '\\Device\\' + i
        else:
            print "No obsfucated or stack strings found :("
