import idc
import idautils
import idaapi
#Originally written by/modified from NCC Group's DriverBuddy https://github.com/nccgroup/DriverBuddy/tree/master/DriverBuddy

names = set()

def cb(ea, name, ord):
    names.add(name)
    return True
    
#NDIS, Legacy printer?, Win USB, User Mode?
def driver_type():

    implist = idaapi.get_import_module_qty()

    for i in range(0, implist):
        name = idaapi.get_import_module_name(i)
        idaapi.enum_import_names(i, cb)
    for i in names:
        if name == "FltRegisterFilter":
            return "Mini-Filter"
        elif name == "WdfVersionBind":
            return "WDF"
        elif name == "StreamClassRegisterMinidriver":
            return "Stream Minidriver"
        elif name == "KsCreateFilterFactory":
            return "AVStream"
        elif name == "PcRegisterSubdevice":
            return "PortCls"
    return "WDM"

def is_driver():
    exports = set(x[3] for x in idautils.Entries())
    return 'DriverEntry' in exports