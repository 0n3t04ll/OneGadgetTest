# OneGadgetTest
OneGadgetTest (ogt) is a gdb plugin to help pwner quickly check constraints of one gadget has been satisfied or not.
This plugin is very simple and probably has some mistakes, feel free to correct it :)
## Requirements
* one_gadget
* gdb
## Usage
* `ogt`
	ogt command will use one_gadget to collect constraints and check the constraints has been satisfied or not.
* `ogt <fix rsp>`
	After call instruction, rsp will minus 8 cause of push return address, `ogt -8` will plus -8 first then check constraints.
## Reference
* [1] https://www-zeuthen.desy.de/unix/unixguide/infohtml/gdb/Python-API.html#Python-API
* [2] https://github.com/david942j/one_gadget
