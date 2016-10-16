# Windows Driver Plugin

An IDA Pro plugin to help when working with IOCTL codes or reversing Windows drivers.

##Installation
Just drop 'win_driver_plugin.py' file and the 'win_driver_plugin' folder into IDA's plugin directory.   
If you want [FLOSS](https://github.com/fireeye/flare-floss) to be used when hunting for device names, you can install FLOSS with the following commands:   
`pip install https://github.com/williballenthin/vivisect/zipball/master   
pip install https://github.com/fireeye/flare-floss/zipball/master`

##Shortcuts

*Ctrl+Alt+A* => Find device name    
*Ctrl+Alt+S* => Find the dispatch function    
*Ctrl+Alt+D* => Decode currently selected IOCTL code   

##Usage
###Finding device names
![](/screenshots/find_device_random_avg_driver.PNG)   
![](/screenshots/find_device_name_capcom.PNG)   
###Finding dispatch functions
![](/screenshots/find_dispatch_random_avg_driver.PNG)   
![](/screenshots/find_dispatch_different_avg_driver_fail.PNG)   
###Decoding IOCTL codes
![](/screenshots/decode_ioctl_capcom_decoded.PNG)   
![](/screenshots/decode_ioctl_summary_table.PNG)   
![](/screenshots/decode_ioctl_mark_ioctl_invalid.PNG)   
![](/screenshots/decode_ioctl_mark_invalid_only_delete_define.PNG)   
![](/screenshots/decode_ioctl_display_all_defines.PNG)   
![](/screenshots/decode_all_ioctls_fail.PNG)   
##Acknowledgements
The IOCTL code parsing functions are mostly based off of Satoshi Tanda's https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py   
The original code for adding items to the right-click menu (and possibly some other random snippets) came from 'herrcore' https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c   
The logic for calling floss and the unicode string finding functions are taken from https://github.com/fireeye/flare-floss   
