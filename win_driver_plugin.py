#!/usr/bin/python
"""Decodes 32-Bit Windows Device I/O control codes.

Author:
    Sam Brown but heavily borrowing from Satoshi Tanda:
        https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py
    and 'herrcore':
        https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c

Description:
    Decodes Windows Device I/O control code into DeviceType, FunctionCode,
    AccessType, MethodType and a useable C define.

To decode a single code:
    1. Select an interesting IOCTL code in the disassemble window.
    2. Hit Ctrl-Alt-D or select Edit/Plugins/Windows IOCTL code decoder

"""

import idc
import idaapi
import idautils

import win_driver_plugin.device_finder as device_finder
import win_driver_plugin.ioctl_decoder as ioctl_decoder

# Used for creating actions exposed in the menu and via hot keys
class UiAction(idaapi.action_handler_t):
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
    # If the address is already commented append the new comment to the existing comment
    current_comment = idc.Comment(pos)
    if not current_comment:
        idc.MakeComm(pos, string)
    elif string not in current_comment:
        idc.MakeComm(pos, current_comment + " " + string)


def get_operand_value(addr):
    return idc.GetOperandValue(addr, 1) & 0xffffffff


# Creates a pop up dialogue with all indexed IOCTL code definitions inside of a multi line text box
class DisplayIOCTLSForm(idaapi.Form):
    def __init__(self):
        Form.__init__(
                        self,
                        """Decoded IOCTLs
                        <:{text}>
                        """, {
                            "text": Form.MultiLineTextControl()
                        }
        )

        self.Compile()
        self.text.value = "\n".join(get_all_defines())
        self.Execute()


# Simple container to keep track of decode IOCTL codes and codes marked as invalid
class IOCTLParser:
    def __init__(self):
        self.ioctl_locs = set()
        self.invalid_ioctls = set()

    def get_valid_ioctls(self):
        return self.ioctl_locs - self.invalid_ioctls

    def add_ioctl(self, ioctl):
        self.ioctl_locs.add(ioctl)

    def add_invalid_ioctl(self, ioctl):
        self.invalid_ioctls.add(ioctl)

    def remove_ioctl(self, ioctl):
        self.ioctl_locs.remove(ioctl)

    def print_table(self, ioctls):
        print "%s | %s | %-40s | %s | %21s | %s" % ("Address", "IOCTL Code", "Device", "Function", "Method", "Access")
        for addr, ioctl_code in ioctls:
            function = ioctl_decoder.get_function(ioctl_code)
            device_name, device_code = ioctl_decoder.get_device(ioctl_code)
            method_name, method_code = ioctl_decoder.get_method(ioctl_code)
            access_name, access_code = ioctl_decoder.get_access(ioctl_code)
            all_vars = (addr, ioctl_code, device_name, device_code, function, method_name, method_code, access_name, access_code)
            print "0x%X | 0x%X | %-31s (0x%X) | 0x%-6X | %17s (%d) | %s (%d)" % all_vars


def find_all_ioctls():
    ioctls = []
    addr = idc.ScreenEA()
    f = idaapi.get_func(addr)
    fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    for block in fc:
        penultimate_inst = idc.PrevHead(idc.PrevHead(block.endEA))
        last_inst = idc.PrevHead(block.endEA)
        if idc.GetMnem(penultimate_inst) in ['cmp', 'sub'] and idc.GetOpType(penultimate_inst, 1) == 5:
            if idc.GetMnem(last_inst) == 'jz':
                ioctl_parser.add_ioctl(penultimate_inst)
    for inst in ioctl_parser.get_valid_ioctls():
        value = get_operand_value(inst)
        ioctls.append((inst, value))
    return ioctls


def decode_all_ioctls():
    ioctls = find_all_ioctls()
    for addr, ioctl_code in ioctls:
        define = ioctl_decoder.get_define(ioctl_code)
        make_comment(addr, define)
    ioctl_parser.print_table(ioctls)


def get_all_defines():
    defines = []
    for inst in ioctl_parser.get_valid_ioctls():
        value = get_operand_value(inst)
        define = ioctl_decoder.get_define(value)
        defines.append(define)
    return defines


# Gets the current selected address and decodes the second parameter to the instruction if it exists/is an immediate
# then adds the C define for the code as a comment and prints a summary table of all decoded IOCTL codes.
def get_position_and_translate():
    pos = idc.ScreenEA()
    if idc.GetOpType(pos, 1) != 5:   # Check the second operand to the instruction is an immediate
        return
    ioctl_parser.add_ioctl(pos)
    value = get_operand_value(pos)
    define = ioctl_decoder.get_define(value)
    make_comment(pos, define)
    # Print summary table each time a new IOCTL code is decoded
    ioctls = []
    for inst in ioctl_parser.ioctl_locs:
        value = get_operand_value(inst)
        ioctls.append((inst, value))
    ioctl_parser.print_table(ioctls)


def find_dispatch_by_struct_index():
    out = set()
    for function_ea in idautils.Functions():
        flags = GetFunctionFlags(function_ea)
        # skip library functions
        if flags & FUNC_LIB:
            continue
        func = idaapi.get_func(function_ea)
        addr = func.startEA
        while addr < func.endEA:
            if GetMnem(addr) == 'mov':
                if '+70h' in GetOpnd(addr, 0) and idc.GetOpType(addr, 1) == 5:
                    out.add(GetOpnd(addr, 1))
            addr = idc.NextHead(addr)
    return out


def find_dispatch_by_cfg():
    out = []
    called = set()
    caller = dict()
    # Loop through all the functions in the binary
    for function_ea in idautils.Functions():
        flags = GetFunctionFlags(function_ea)
        # skip library functions
        if flags & FUNC_LIB:
            continue
        f_name = GetFunctionName(function_ea)
        # For each of the incoming references
        for ref_ea in CodeRefsTo(function_ea, 0):
            called.add(f_name)
            # Get the name of the referring function
            caller_name = GetFunctionName(ref_ea)
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
    index_funcs = find_dispatch_by_struct_index()
    cfg_funcs = find_dispatch_by_cfg()
    if len(index_funcs) == 0:
        print "Based off of basic CFG analysis the likely dispatch function is: " + cfg_funcs[0]
    elif len(index_funcs) == 1:
        func = index_funcs.pop()
        if func in cfg_funcs:
            print "The likely dispatch function is: " + func
        else:
            print "Based off of basic the offset it is loaded at a potential dispatch function is: " + func
            print "Based off of basic CFG analysis the likely dispatch function is: " + cfg_funcs[0]
    else:
        print "Potential dispatch functions: "
        for i in index_funcs:
            if i in cfg_funcs:
                print i


class ActionHandler(idaapi.action_handler_t):
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DecodeHandler(ActionHandler):
    def activate(self, ctx):
        get_position_and_translate()


class DecodeAllHandler(ActionHandler):
    def activate(self, ctx):
        decode_all_ioctls()


class ShowAllHandler(ActionHandler):
    def activate(self, ctx):
        DisplayIOCTLSForm()


class InvalidHandler(ActionHandler):
    def activate(self, ctx):
        pos = idc.ScreenEA()
        ioctl_parser.remove_ioctl(pos)
        ioctl_parser.add_invalid_ioctl(pos)


def register_dynamic_action(form, popup, description, handler):
    # Note the 'None' as action name (1st parameter).
    # That's because the action will be deleted immediately
    # after the context menu is hidden anyway, so there's
    # really no need giving it a valid ID.
    action = idaapi.action_desc_t(None, description, handler)
    idaapi.attach_dynamic_action_to_popup(form, popup, action, None)


class WinDriverHooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
        tft = idaapi.get_tform_type(form)
        if tft != idaapi.BWN_DISASM:
            return

        pos = idc.ScreenEA()
        # If the second argument to the current selected instruction is an immediately
        # then give the option to decode it.
        if idc.GetOpType(pos, 1) == 5:
            register_dynamic_action(form, popup, 'Decode IOCTL', DecodeHandler())
            if pos in ioctl_parser.ioctl_locs:
                register_dynamic_action(form, popup, 'Invalid IOCTL', InvalidHandler())
        if idaapi.get_func(pos).startEA == pos:
            register_dynamic_action(form, popup, 'Decode All IOCTLs', DecodeAllHandler())
        register_dynamic_action(form, popup, 'Show All IOCTLs', ShowAllHandler())


class WinDriverPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Decodes Windows Device I/O control codes into DeviceType, FunctionCode, AccessType and MethodType."
    help = ''
    wanted_name = 'Windows IOCTL code decoder'
    # No hotkey for the plugin - individuals actions have thier own
    wanted_hotkey = ""

    def init(self):
        global ioctl_parser
        ioctl_parser = IOCTLParser()
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
        return idaapi.PLUGIN_OK

    def run(self, _=0):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return WinDriverPlugin()
