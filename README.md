# ioctl_plugin

A tool to help when dealing with IOCTL codes and Windows driver IOCTL dispatch functions.

##Author
I heavily borrowed from Satoshi Tanda (https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py) and 'herrcore' (https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c) while writing this.

##Usage

Find an IOCTL code:   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/before_single_decode.PNG)    
By using the right click context menu and selecting 'Decode IOCTL' a comment will added after the instruction with a C define for IOCTL code, this can also achieved using 'CTRL+ALT+D'.   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/context_menu_right_click_asm.PNG)    
Additionally once an IOCTL has been decoded a new 'Invalid IOCTL' option will appear on the right click context menu - use this to unmark an IOCTL code so it doesn't appear in any summaries.   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/after_single_decode.PNG)   
Each time one or more IOCTL codes are decoded a summary table will be printed in IDA's output window.   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/summary_table.PNG)   
If you right click on a function name will in the graph/asm view another new option 'Decode all IOCTLs' will appear.    
This will attempt to decode all of the IOCTL codes present in the function, this is aimed at being used in a drivers IOCTL dispatch function and is very basic so will likely fail for a lot of drivers.   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/context_menu_right_click_function_name.PNG)   
Before decode all is selected:   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/before_decode_all.PNG)   
After decode all is selected:   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/after_decode_all.PNG)   
The 'Show all IOCTLs' is present on the right click menu as well - this will open a form with a text box containing the C defines for all the IOCTL codes decoded in the current session.   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/show_all.PNG)
Using the shortcut 'CTRL+ALT+S' it is possible to attempt to find the IOCTL handler/dispatch function for a driver - this is done by finder the function that calls the most other functions but is not called by any functions itself.   
![](https://raw.githubusercontent.com/sam-b/ioctl_plugin/master/screenshots/dispatch_table_finder.PNG)
##Installation
Just drop 'ioctl_plugin.py' into IDA's plugin directory.