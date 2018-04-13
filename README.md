# Windows Driver Plugin

An IDA Pro plugin to help when working with IOCTL codes or reversing Windows drivers.

## Installation

Just drop the 'win_driver_plugin.py' file and the 'win_driver_plugin' folder into IDA's plugin directory.   
If you want [FLOSS](https://github.com/fireeye/flare-floss) to be used when hunting for device names, you can install FLOSS with the following commands:   
```
pip install https://github.com/williballenthin/vivisect/zipball/master   
pip install https://github.com/fireeye/flare-floss/zipball/master
```
If you want to use Angr to find IOCTL codes used in the dispatch function, the following links provide potential install instructions.   
[http://angr.horse](http://angr.horse)   
[https://github.com/andreafioraldi/angr-win64-wheels](https://github.com/andreafioraldi/angr-win64-wheels)   

## Shortcuts

*Ctrl+Alt+A* => Find potential device names    
*Ctrl+Alt+S* => Find the dispatch function   
*Ctrl+Alt+D* => Decode currently selected IOCTL code  
*Ctrl+Alt+Z* => Dump pooltags 

## Usage

### Finding device names

Using *Ctrl+Alt+A* it's possible to attempt to the find the drivers registered device paths, for example we get several potential paths when inspecting a random AVG driver:   
![](/screenshots/find_device_random_avg_driver.PNG)   
If no paths can be found by looking at Unicode strings inside the binary then FLOSS will be used in an attempt to find obsfucated paths, for example inspecting the infamous [capcom driver](http://www.theregister.co.uk/2016/09/23/capcom_street_fighter_v/):   
![](/screenshots/find_device_name_capcom.PNG)   

### Finding dispatch functions

Using *Ctrl+Alt+S* it's possible to attempt to find the currently inspected drivers dispatch function, this is quite hacky but seems to work most of the time - here's an example of this working on a random AVG driver:   
![](/screenshots/find_dispatch_random_avg_driver.PNG)  
Trying this on a different AVG driver leads to it failing completely, in this case because the drivers IOCTL handler is basically a stub which sends some requests to a different function begore passing most to the actual IOCTL handler    
![](/screenshots/find_dispatch_different_avg_driver_fail.PNG)   

### Decoding IOCTL codes

By right-clicking on a potential IOCTL code a context menu option can be used to decode the value, alternatively *Ctrl+Alt+D* can be used.   
![](/screenshots/decode_ioctl_capcom_decoded.PNG)   
This will print a table with all decoded IOCTL codes each time a new one is decoded:   
![](/screenshots/decode_ioctl_summary_table.PNG)   
By right-clicking on a decoded IOCTL code it's possible to mark it as invalid:   
![](/screenshots/decode_ioctl_mark_ioctl_invalid.png)   
This will leave any non-IOCTL define based comment contents intact.   
![](/screenshots/decode_ioctl_mark_invalid_only_delete_define.PNG)   
The right-click menu also included a display all defines option which display the CTL_CODE definitions for all IOCTL codes decoded in the current session:   
![](/screenshots/decode_ioctl_display_all_defines.PNG)   
If you right click on the first instruction of the function you believe to be the IOCTL dispatcher a decode all options appears, this attempt to decode all IOCTL codes it can find in the function. This is super hacky but can speed things up most of the time.   
![](/screenshots/decode_all_ioctls_fail.PNG)   
If you want to do this in a smarter way and can get [Angr](http://angr.horse) installed successfully, the 'Decode IOCTLs using Angr' option shown below will use symbolic execution to attempt to recover all IOCTL codes. This will deal with jump tables, optimizations etc whereas the dumb method is just looking for comparisons to constants. 
![](/screenshots/angr_decode_option.png)

### Viewing IOCTL codes 

If you've decoder one or more IOCTLs a new option appears on the plugins right click context menu.

![](/screenshots/view_all.png)

This will take you to a new tab which shows all the IOCTLs which have been found. 

![](/screenshots/define_tab.PNG)

Right clicking on any IOCTL opens up some more commands, such as copying them to the clipboard or attempting to load the driver and send them.

![](/screenshots/define_tab_right_click.PNG)

### Dumping pool tags 

Using *Ctrl+Alt+Z* it's possible to dump the pooltags in use by the binary in a format which works with pooltags.txt. This means the output can be copy pasted at the end of the file and then be picked up by windbg etc.
![](/screenshots/dump_pool_tags.PNG)

## Acknowledgements

The IOCTL code parsing functions are mostly based off of Satoshi Tanda's https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py   
The original code for adding items to the right-click menu (and possibly some other random snippets) came from 'herrcore' https://gist.github.com/herrcore/b3143dde185cecda7c1dee7ffbce5d2c   
The logic for calling floss and the unicode string finding functions are taken from https://github.com/fireeye/flare-floss   
The driver type identification code logic is taken from NCC Group's DriverBuddy plugin https://github.com/nccgroup/DriverBuddy    

## License

This code is released under a 3-clause BSD License. See the LICENSE file for full details.