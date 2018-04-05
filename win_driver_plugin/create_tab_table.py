import idc
import idaapi
from idaapi import Choose2
import driverlib
import re
import ctypes
import ioctl_decoder as ioctl_decoder
import sys

# yoinked from https://stackoverflow.com/a/25678113
OpenClipboard = ctypes.windll.user32.OpenClipboard
EmptyClipboard = ctypes.windll.user32.EmptyClipboard
GetClipboardData = ctypes.windll.user32.GetClipboardData
SetClipboardData = ctypes.windll.user32.SetClipboardData
CloseClipboard = ctypes.windll.user32.CloseClipboard
CF_UNICODETEXT = 13

GlobalAlloc = ctypes.windll.kernel32.GlobalAlloc
GlobalLock = ctypes.windll.kernel32.GlobalLock
GlobalUnlock = ctypes.windll.kernel32.GlobalUnlock
GlobalSize = ctypes.windll.kernel32.GlobalSize
GMEM_MOVEABLE = 0x0002
GMEM_ZEROINIT = 0x0040

unicode_type = type(u'')

class stop_unload_handler_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print "Admin privileges required"
            return
        name = idc.GetInputFile().split('.')[0]
        driver = driverlib.Driver(idc.GetInputFilePath(),name)
        stopped = driver.stop()
        unloaded = driver.unload()

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM

class start_load_handler_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print "Admin privileges required"
            return
        name = idc.GetInputFile().split('.')[0]
        driver = driverlib.Driver(idc.GetInputFilePath(),name)
        loaded = driver.load()
        started = driver.start()
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM        
        
class send_ioctl_handler_t(idaapi.action_handler_t):
    def __init__(self, items):
        idaapi.action_handler_t.__init__(self)
        self.items = items
        
    def activate(self, ctx):
        ind = ctx.chooser_selection.at(0)
        ioctl = self.items[ind - 1]
        name = idc.GetInputFile().split('.')[0]
        driver = driverlib.Driver(idc.GetInputFilePath(),name)
        DisplayIOCTLSForm(ioctl, driver)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM

class copy_defines_handler_t(idaapi.action_handler_t):
    def __init__(self, items):
        idaapi.action_handler_t.__init__(self)
        self.items = items

    def activate(self, ctx):
        defines = []
        for item in self.items:
            defines.append(item[5])
        print(defines)
        paste('\n'.join(defines))

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM

class remove_ioctl(idaapi.action_handler_t):
	
	def __init__(self, items):
		idaapi.action_handler_t.__init__(self)
		self.items = items 
		
	def activate(self, ctx):
		# get item and remove 
		ind = ctx.chooser_selection.at(0)
		ioctl = self.items[ind - 1]
		pos = int(ioctl[0], 16)
		define = ioctl[5]
		global ioctl_tracker
		for (addr, val) in ioctl_tracker.ioctls:
			if addr == pos:
				code = val
				break
		# Get current comment for this instruction and remove the C define from it, if present
		comment = idc.Comment(pos)
		comment = comment.replace(define, "")
		idc.MakeComm(pos, comment)
		# Remove the ioctl from the valid list and add it to the invalid list to avoid 'find_all_ioctls' accidently re-indexing it.
		ioctl_tracker.remove_ioctl(pos, code)
		
	def update(self, ctx):
		return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM

class MyChoose2(Choose2):

    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            [ ["Address", 5], ["Function", 5], ["Device", 15], ["Method", 15], ["Access", 30], ["C define", 100] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = items
        self.icon = 5
        self.selcount = 0
        self.modal = modal
        self.popup_names = ["Insert", "Delete", "Refresh"]

    def OnClose(self):
        pass

    def OnSelectLine(self, n):

		item = self.items[n]

		jump_ea = int(item[0], 16)
		# Only jump for valid addresses
		if idaapi.IDA_SDK_VERSION < 700:
			valid_addr = idc.isEnabled(jump_ea)
		else:
			valid_addr = idc.is_mapped(jump_ea)
		if valid_addr:
			idc.Jump(jump_ea)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnDeleteLine(self, n):
        global ioctl_tracker
        ioctl_tracker.remove_ioctl(int(self.items[n][0], 16))
        del self.items[n]
        return n

    def OnRefresh(self, n):
        self.items = get_all_defines()
        return n

    def OnGetIcon(self, n):
        return -1

    def show(self):
        return self.Show(self.modal) >= 0

    def OnGetLineAttr(self, n):
        pass

def get_operand_value(addr):
    """Returns the value of the second operand to the instruction at `addr` masked to be a 32 bit value"""

    return idc.GetOperandValue(addr, 1) & 0xffffffff

        
def get_all_defines():
    """Returns the C defines for all ICOTL codes which have been marked during the current session"""

    global ioctl_tracker
    defines = []
    for (addr, value) in ioctl_tracker.ioctls:
        function = ioctl_decoder.get_function(value)
        device_name, device_code = ioctl_decoder.get_device(value)
        method_name, method_code = ioctl_decoder.get_method(value)
        access_name, access_code = ioctl_decoder.get_access(value)
        define = ioctl_decoder.get_define(value)
        defines.append(["0x%X" % (addr,), "0x%X" % (function,), "%s (0x%X)" % (device_name, device_code), "%s (0x%X)" % (method_name, method_code), "%s (0x%X)" % (access_name, access_code), define])
    return defines
        
def create_ioctl_tab(tracker, modal=False):
    global ioctl_tracker
    ioctl_tracker = tracker
    items = get_all_defines()
    idaapi.register_action(
        idaapi.action_desc_t(
            "choose2:remove_ioctl",
            "Invalid IOCTL",
            remove_ioctl(items)
        )
    )
    action = "send_ioctl"
    actname = "choose2:act%s" % action
    idaapi.register_action(
        idaapi.action_desc_t(
            actname,
            "Send IOCTL",
            send_ioctl_handler_t(items)))
    idaapi.register_action(
        idaapi.action_desc_t(
            "choose2:actcopy_defines",
            "Copy All Defines",
            copy_defines_handler_t(items)))
            
    idaapi.register_action(
        idaapi.action_desc_t(
            "choose2:actstop_unload",
            "Stop & Unload Driver",
            stop_unload_handler_t()))
    idaapi.register_action(
        idaapi.action_desc_t(
            "choose2:actstart_load",
            "Load & Start Driver",
            start_load_handler_t()))
    global c
    c = MyChoose2("IOCTL Code Viewer", items, modal=modal)
    r = c.show()
    form = idaapi.get_current_tform()
    idaapi.attach_action_to_popup(form, None, "choose2:act%s" % action)
    idaapi.attach_action_to_popup(form, None, "choose2:actcopy_defines")
    idaapi.attach_action_to_popup(form, None, "choose2:actstop_unload")
    idaapi.attach_action_to_popup(form, None, "choose2:actstart_load")
    idaapi.attach_action_to_popup(form, None, "choose2:remove_ioctl")

def paste(s):
    if not isinstance(s, unicode_type):
        s = s.decode('mbcs')
    data = s.encode('utf-16le')
    OpenClipboard(None)
    EmptyClipboard()
    handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data) + 2)
    pcontents = GlobalLock(handle)
    ctypes.memmove(pcontents, data, len(data))
    GlobalUnlock(handle)
    SetClipboardData(CF_UNICODETEXT, handle)
    CloseClipboard()
    
class DisplayIOCTLSForm(idaapi.Form):
    """Creates a pop up dialog with all indexed IOCTL code definitions inside of a multi line text box"""

    def __init__(self, ioctl, driver):
        idaapi.Form.__init__(
                        self,
                        """Send IOCTL
                        {form_change}
                        <#Input Buffer#~I~nput Buffer:{in_buf}>
                        <#Input Buffer Size#~I~nput Buffer Size:{in_size}>
                        <#Output Buffer#~O~utput Buffer:{out_buf}>
                        <#Output Buffer Size#~O~utput Buffer Size:{out_size}>
                        <#Send IOCTL#~S~end IOCTL:{sendIOCTL}>
                        """, {
                            "form_change": idaapi.Form.FormChangeCb(self.form_change),
                            "in_buf": idaapi.Form.MultiLineTextControl(),
                            "out_buf": idaapi.Form.MultiLineTextControl(),
                            "in_size": idaapi.Form.NumericInput(),
                            "out_size": idaapi.Form.NumericInput(),
                            "sendIOCTL": idaapi.Form.ButtonInput(self.send_ioctl)
                        }
        )
        self.driver = driver
        global ioctl_tracker
        for inst in ioctl_tracker.ioctl_locs:
            value = get_operand_value(inst)
            function = ioctl_decoder.get_function(value)
            if function == int(ioctl[1],16):
                self.ioctl = value
        self.Compile()
        self.in_size.value = 0x20
        self.out_size.value = 0x20
        self.in_buf.value = "\\x41" * 0x20
        self.Execute()

    def form_change(self,fid):
        if fid == self.in_size.id:
            val = self.GetControlValue(self.in_size)
            self.in_size.value = val
        elif fid == self.out_size.id:
            val = self.GetControlValue(self.out_size)
            self.out_size.value = val
        elif fid == self.out_buf.id:
            val = self.GetControlValue(self.out_buf)
            self.out_buf.value = val.value
        elif fid == self.in_buf.id:
            val = self.GetControlValue(self.in_buf)
            self.in_buf.value = val.value
        elif fid == -1:
            pass
        elif fid == -2:
            self.Close(-1)
        elif fid == self.sendIOCTL.id:
            pass
        else:
            print fid
            
    def send_ioctl(self,fid):
        if not self.driver.handle:
            self.driver.open_device()
        in_buf = self.in_buf.value.decode('string_escape')
        in_size = self.in_size.value
        out_size = self.out_size.value
        out_buf = self.out_buf.value.decode('string_escape')
        self.driver.send_ioctl(self.ioctl, in_buf, in_size, out_buf, out_size)