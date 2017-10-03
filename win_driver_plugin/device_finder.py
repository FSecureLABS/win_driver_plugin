""" Device name finding functions. Using a unicode string search and searching for stack based and obsfucated strings.
 A bulk of this is taken from https://github.com/fireeye/flare-floss"""
import mmap
import re
import collections
import idc
import logging

ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
SLICE_SIZE = 4096

String = collections.namedtuple("String", ["s", "offset"])


def buf_filled_with(buf, character):
    """Returns true if the buffer is filled with the recurring character"""

    dupe_chunk = character * SLICE_SIZE
    for offset in xrange(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset: offset + SLICE_SIZE]
        if dupe_chunk[:len(new_chunk)] != new_chunk:
            return False
    return True


def extract_unicode_strings(buf, n=4):
    """Extract naive UTF-16 strings from the given binary data."""

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
    """Returns all unicode strings within the binary currently being analysed in IDA which might be device names"""

    path = idc.GetInputFile()
    min_length = 4
    possible_names = set()
    with open(path, "rb") as f:
        b = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for s in extract_unicode_strings(b, n=min_length):
            s_str = str(s.s)
            if s_str.startswith('\\Device\\') or s_str.startswith('\\DosDevices\\'):
                possible_names.add(str(s.s))
    return possible_names


def find_unicode_device_name():
    """Attempts to find and output potential device names - returning False if none are found so further analysis can be done"""

    possible_names = get_unicode_device_names()
    if len(possible_names) == 1 or len(possible_names) == 2:
        if '\\Device\\' in possible_names or '\\DosDevices\\' in possible_names:
            if len(possible_names) == 1:
                print "The Device prefix was found but no full device paths, the device name is likely obsfucated or created on the stack."
                return False
            elif '\\Device\\' in possible_names and '\\DosDevices\\' in possible_names:
                print "The Device prefixs were found but no full device paths, the device name is likely obsfucated or created on the stack."
                return False
            else:
                print "Potential device name: "
                for i in possible_names:
                    if i != '\\Device\\' and i != '\\DosDevices\\':
                        print i
            return True
        else:
            print "Potential device names: "
            for i in possible_names:
                print i
            return True
    elif len(possible_names) > 2:
        print "Possible devices names found:"
        for i in possible_names:
            print "\t" + i
        return True
    else:
        print "No potential device names found - it may be obsfucated or created on the stack in some way."
        return False


def search():
    """
    Attempts to find potential device names in the currently opened binary, it starts by searching for unicode device names,
    if this fails then it utilises FLOSS to search for stack based and obsfucated strings.
    """

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
            return
        logging.basicConfig() #To avoid logger handler not found errors, from https://github.com/fireeye/flare-floss/blob/66f67a49a38ae028a5e86f1de743c384d5271901/scripts/idaplugin.py#L154
        logging.getLogger('vtrace.platforms.win32').setLevel(logging.ERROR)
        sample_file_path = idc.GetInputFile()

        try:
            vw = viv_utils.getWorkspace(sample_file_path, should_save=False)
        except Exception, e:
            print("Vivisect failed to load the input file: {0}".format(e.message))
            return

        functions = set(vw.getFunctions())
        plugins = floss.main.get_all_plugins()
        device_names = set()

        stack_strings = floss.stackstrings.extract_stackstrings(vw, functions, 4, no_filter=True)
        for i in stack_strings:
            device_names.add(i)
        dec_func_candidates = floss.identification_manager.identify_decoding_functions(vw, plugins, functions)
        decoded_strings = floss.main.decode_strings(vw, dec_func_candidates, 4, no_filter=True)
        if len(decoded_strings) > 0:
            for i in decoded_strings:
                device_names.add(str(i.s))
            print "Potential device names from obsfucated or stack strings:"
            for i in device_names:
                print i
        else:
            print "No obsfucated or stack strings found :("
