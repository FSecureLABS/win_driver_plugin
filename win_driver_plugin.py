"""Decodes 32-Bit Windows Device I/O control codes.

Author:
    Sam Brown

Description:
    *  Discover driver device names by search through present Unicode strings and if not found
    searches for stack based strings or obfuscated strings which could be the device name
    *  Decodes Windows Device I/O control code into DeviceType, FunctionCode,
    AccessType, MethodType and a usable C define.
    *  Attempts to locate the driver dispatch handler by doing some basic CFG analysis and checking
       offsets at which function pointers are loaded into memory.
"""

import idc
import idaapi
import idautils

import win_driver_plugin.device_finder as device_finder
import win_driver_plugin.ioctl_decoder as ioctl_decoder
import win_driver_plugin.create_tab_table as create_tab_table
import win_driver_plugin.device_type as device_type
import win_driver_plugin.angr_analysis as angr_analysis
import win_driver_plugin.dump_pool_tags as dump_pool_tags

class UiAction(idaapi.action_handler_t):
    """Simple wrapper class for creating action handlers which add options to menu's and are triggered via hot keys"""

    def __init__(self, id, name, tooltip, menuPath, callback, shortcut):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.tooltip = tooltip
        self.menuPath = menuPath
        self.callback = callback
        self.shortcut = shortcut

    def registerAction(self):
        action_desc = idaapi.action_desc_t(
            self.id,
            self.name,
            self,
            self.shortcut,
            self.tooltip,
            0
        )
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
            return False
        return True

    def unregisterAction(self):
        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def make_comment(pos, string):
    """
    Creates a comment with contents `string` at address `pos`.
    If the address is already commented append the new comment to the existing comment
    """
    
    current_comment = idc.Comment(pos)
    if not current_comment:
        idc.MakeComm(pos, string)
    elif string not in current_comment:
        idc.MakeComm(pos, current_comment + " " + string)


def get_operand_value(addr):
    """Returns the value of the second operand to the instruction at `addr` masked to be a 32 bit value"""

    return idc.GetOperandValue(addr, 1) & 0xffffffff

class IOCTLTracker:
    """A simple container to keep track of decoded IOCTL codes and codes marked as invalid"""

    def __init__(self):
        self.ioctl_locs = set()
        self.ioctls = []
    
    def add_ioctl(self, addr, value):
        self.ioctl_locs.add(addr)
        self.ioctls.append((addr, value))

    def remove_ioctl(self, addr, value):
        self.ioctl_locs.remove(addr)
        self.ioctls.remove((addr, value))
		
    def print_table(self, ioctls):
        print "%-10s | %-10s | %-42s | %-10s | %-22s | %s" % ("Address", "IOCTL Code", "Device", "Function", "Method", "Access")
        for (addr, ioctl_code) in ioctls:
            function = ioctl_decoder.get_function(ioctl_code)
            device_name, device_code = ioctl_decoder.get_device(ioctl_code)
            method_name, method_code = ioctl_decoder.get_method(ioctl_code)
            access_name, access_code = ioctl_decoder.get_access(ioctl_code)
            all_vars = (addr, ioctl_code, device_name, device_code, function, method_name, method_code, access_name, access_code)
            print "0x%-8X | 0x%-8X | %-31s 0x%-8X | 0x%-8X | %-17s %-4d | %s (%d)" % all_vars


def find_all_ioctls():
    """
    From the currently selected address attempts to traverse all blocks inside the current function to find all immediate values which
    are used for a comparison/sub immediately before a jz. Returns a list of address, second operand pairs.
    """
    
    ioctls = []
    # Find the currently selected function and get a list of all of it's basic blocks
    addr = idc.ScreenEA()
    f = idaapi.get_func(addr)
    fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    for block in fc:
        # grab the last two instructions in the block 
        last_inst = idc.PrevHead(block.endEA)
        penultimate_inst = idc.PrevHead(last_inst)
        # If the penultimate instruction is cmp or sub against an immediate value immediately preceding a 'jz' 
        # then it's a decent guess that it's an IOCTL code (if this is a dispatch function)
        if idc.GetMnem(penultimate_inst) in ['cmp', 'sub'] and idc.GetOpType(penultimate_inst, 1) == 5:
            if idc.GetMnem(last_inst) == 'jz':
                value = get_operand_value(penultimate_inst)
                ioctls.append((penultimate_inst, value))
                ioctl_tracker.add_ioctl(penultimate_inst, value)
    return ioctls

def track_ioctls(ioctls):
    global ioctl_tracker
    for addr, ioctl_code in ioctls:
        ioctl_tracker.add_ioctl(addr, ioctl_code)
        define = ioctl_decoder.get_define(ioctl_code)
        make_comment(addr, define)
    ioctl_tracker.print_table(ioctls)

def decode_all_ioctls():
    """Attempts to locate all the IOCTLs in a function and decode them all"""

    global ioctl_tracker
    ioctls = find_all_ioctls()
    track_ioctls(ioctls)
	
def decode_angr():
	"""Attempts to locate all the IOCTLs in a function and decode them all using symbolic execution"""
	
	path = idaapi.get_input_file_path()
	addr = idc.ScreenEA()
	ioctls = angr_analysis.angr_find_ioctls(path, addr)
	track_ioctls(ioctls)

def get_position_and_translate():
    """
    Gets the current selected address and decodes the second parameter to the instruction if it exists/is an immediate
    then adds the C define for the code as a comment and prints a summary table of all decoded IOCTL codes.
    """

    pos = idc.ScreenEA()
    if idc.GetOpType(pos, 1) != 5:   # Check the second operand to the instruction is an immediate
        return
    
    value = get_operand_value(pos)
    ioctl_tracker.add_ioctl(pos, value)
    define = ioctl_decoder.get_define(value)
    make_comment(pos, define)
    # Print summary table each time a new IOCTL code is decoded
    ioctls = []
    for inst in ioctl_tracker.ioctl_locs:
        value = get_operand_value(inst)
        ioctls.append((inst, value))
    ioctl_tracker.print_table(ioctls)


def find_dispatch_by_struct_index():
    """Attempts to locate the dispatch function based off it being loaded in a structure
    at offset 70h, based off of https://github.com/kbandla/ImmunityDebugger/blob/master/1.73/Libs/driverlib.py """
    
    out = set()
    for function_ea in idautils.Functions():
        flags = idc.get_func_flags(function_ea)
        # skip library functions
        if flags & idc.FUNC_LIB:
            continue
        func = idaapi.get_func(function_ea)
        addr = func.startEA
        while addr < func.endEA:
            if idc.GetMnem(addr) == 'mov':
                if '+70h' in idc.GetOpnd(addr, 0) and idc.GetOpType(addr, 1) == 5:
                    out.add(idc.GetOpnd(addr, 1))
            addr = idc.NextHead(addr)
    return out


def find_dispatch_by_cfg():
    """ 
    Finds the functions in the binary which are not directly called anywhere and counts how many other functions they call,
    returing all functions which call > 0 other functions but are not called themselves. As a dispatch function is not normally directly
    called but will normally many other functions this is a fairly good way to guess which function it is.
    """
        
    out = []
    called = set()
    caller = dict()
    # Loop through all the functions in the binary
    for function_ea in idautils.Functions():
        flags = idc.get_func_flags(function_ea)
        # skip library functions
        if flags & idc.FUNC_LIB:
            continue
        f_name = idc.GetFunctionName(function_ea)
        # For each of the incoming references
        for ref_ea in idautils.CodeRefsTo(function_ea, 0):
            called.add(f_name)
            # Get the name of the referring function
            caller_name = idc.GetFunctionName(ref_ea)
            if caller_name not in caller.keys():
                caller[caller_name] = 1
            else:
                caller[caller_name] += 1
    while True:
        if len(caller.keys()) == 0:
            break
        potential = max(caller, key=caller.get)
        if potential not in called:
            out.append(potential)
        del caller[potential]
    return out


def find_dispatch_function():
    """
    Compares and processes results of `find_dispatch_by_struct_index` and `find_dispatch_by_cfg` 
    to output potential dispatch function addresses
    """

    index_funcs = find_dispatch_by_struct_index()
    cfg_funcs = find_dispatch_by_cfg()
    if len(index_funcs) == 0:
        cfg_finds_to_print = min(len(cfg_funcs),3)
        for i in range(cfg_finds_to_print):
            print "Based off of basic CFG analysis the potential dispatch functions are: " + cfg_funcs[i]
    elif len(index_funcs) == 1:
        func = index_funcs.pop()
        if func in cfg_funcs:
            print "The likely dispatch function is: " + func
        else:
            print "Based off of the offset it is loaded at a potential dispatch function is: " + func
            print "Based off of basic CFG analysis the likely dispatch function is: " + cfg_funcs[0]
    else:
        print "Potential dispatch functions: "
        for i in index_funcs:
            if i in cfg_funcs:
                print i

def get_pool_tags():
	""" Display a list of the pool tags in use by the current driver.
	"""
	
	pooltags = dump_pool_tags.get_all_pooltags()
	print("The following pooltags are in use by the binary: ")
	print(pooltags)

class ActionHandler(idaapi.action_handler_t):
    """Basic wrapper class to avoid all action handlers needing to implement update identically"""

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DecodeHandler(ActionHandler):
    """Wrapper for `get_position_and_translate` used for right-click context menu hook"""

    def activate(self, ctx):
        get_position_and_translate()


class DecodeAllHandler(ActionHandler):
    """Wrapper for `decode_all_ioctls` used for right-click context menu hook"""
    
    def activate(self, ctx):
        decode_all_ioctls()

class DecodeAngrHandler(ActionHandler):
    """Wrapper for `decode_angr` used for right-click context menu hook"""
    
    def activate(self, ctx):
        decode_angr()
		
		
class ShowAllHandler(ActionHandler):
    """Used for Show All option in right-click context menu, creates a `DisplayIOCTLSForm` instance, remaining logic is contained within that class."""

    def activate(self, ctx):
        create_tab_table.create_ioctl_tab(ioctl_tracker)


class InvalidHandler(ActionHandler):
    """
    Only available when right-clicking on an address marked as an IOCTL code location, removes it from the location list 
    and deletes C define comment marking it (but leaves any other comment content at that location intact).
    """
    
    def activate(self, ctx):
        pos = idc.ScreenEA()
        # Get current comment for this instruction and remove the C define from it, if present
        comment = idc.Comment(pos)
        code = get_operand_value(pos)
        define = ioctl_decoder.get_define(code)
        comment = comment.replace(define, "")
        idc.MakeComm(pos, comment)
        # Remove the ioctl from the valid list and add it to the invalid list to avoid 'find_all_ioctls' accidently re-indexing it.
        ioctl_tracker.remove_ioctl(pos, code)


def register_dynamic_action(form, popup, description, handler):
    """Registers a new item in a popup which will trigger a function when selected""" 

    # Note the 'None' as action name (1st parameter).
    # That's because the action will be deleted immediately
    # after the context menu is hidden anyway, so there's
    # really no need giving it a valid ID.
    action = idaapi.action_desc_t(None, description, handler)
    idaapi.attach_dynamic_action_to_popup(form, popup, action, 'Driver Plugin/')


class WinDriverHooks(idaapi.UI_Hooks):
    """Installs hook function which is triggered when popup forms are created and adds extra menu options if it is the right-click disasm view menu"""

    def finish_populating_tform_popup(self, form, popup):
        tft = idaapi.get_tform_type(form)
        if tft != idaapi.BWN_DISASM:
            return

        pos = idc.ScreenEA()
        register_dynamic_action(form, popup, 'Decode All IOCTLs in Function', DecodeAllHandler())
        register_dynamic_action(form, popup, 'Decode IOCTLs using Angr', DecodeAngrHandler())
		# If the second argument to the current selected instruction is an immediately
        # then give the option to decode it.
        if idc.GetOpType(pos, 1) == 5:
            register_dynamic_action(form, popup, 'Decode IOCTL', DecodeHandler())
            if pos in ioctl_tracker.ioctl_locs:
                register_dynamic_action(form, popup, 'Invalid IOCTL', InvalidHandler())
        if len(ioctl_tracker.ioctl_locs) > 0:
            register_dynamic_action(form, popup, 'Show All IOCTLs', ShowAllHandler())


class WinDriverPlugin(idaapi.plugin_t):
    """Main plugin class, registers the various menu items, hot keys and menu hooks as well as initialising the plugin's global state."""

    flags = idaapi.PLUGIN_UNL
    comment = "Decodes Windows Device I/O control codes into DeviceType, FunctionCode, AccessType and MethodType."
    help = ''
    wanted_name = 'Windows IOCTL code decoder'
    # No hot key for the plugin - individuals actions have their own
    wanted_hotkey = ""

    def init(self):
        if device_type.is_driver():
            print("Driver type: {}".format(device_type.driver_type()))
        global ioctl_tracker
        ioctl_tracker = IOCTLTracker()
        global hooks
        hooks = WinDriverHooks()
        hooks.hook()
        device_name = UiAction(
            id="ioctl:find_device_name",
            name="Find Device Name",
            tooltip="Attempts to find the device name.",
            menuPath="Edit/IOCTL/",
            callback=device_finder.search,
            shortcut="Ctrl+Alt+A"
        )
        device_name.registerAction()
        find_dispatch = UiAction(
            id="ioctl:find_dispatch",
            name="Find Dispatch",
            tooltip="Attempts to find the dispatch function.",
            menuPath="Edit/IOCTL/",
            callback=find_dispatch_function,
            shortcut="Ctrl+Alt+S"
        )
        find_dispatch.registerAction()
        decode_ioctl = UiAction(
            id="ioctl:decode",
            name="Decode IOCTL",
            tooltip="Decodes the currently selected constant into its IOCTL details.",
            menuPath="",
            shortcut="Ctrl+Alt+D",
            callback=get_position_and_translate
        )
        decode_ioctl.registerAction()
        pool_tags = UiAction(
            id="ioctl:pools_tags",
            name="Dump Pool Tags",
            tooltip="Attempts to find all pool tags used by the driver and display them a format which be included in pooltags.txt for debugging.",
            menuPath="Edit/IOCTL/",
            shortcut="Ctrl+Alt+Z",
            callback=get_pool_tags
        )
        pool_tags.registerAction()
        return idaapi.PLUGIN_OK

    def run(self, _=0):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return WinDriverPlugin()
