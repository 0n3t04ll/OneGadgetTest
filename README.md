# OneGadgetTest
OneGadgetTest (ogt) is a gdb plugin to help pwner quickly check constraints of one gadget has been satisfied or not.
This plugin is very simple and probably has some mistakes, feel free to correct it :)
## Requirements
* one_gadget
* gdb
## Installation
```
git clone https://github.com/0n3t04ll/OneGadgetTest.git
cd OneGadgetTest
echo "source `pwd`/ogt.py" >> ~/.gdbinit
```

## Usage
```
$gdb ogt
```
ogt command will use one_gadget to collect constraints and check the constraints has been satisfied or not.


```
$gdb ogt <fix rsp>
``` 
After call instruction, rsp will minus 8 cause of push return address, `ogt -8` will plus -8 first then check constraints.

## ScreenShots
The program below is very simple, it just read the input and take it as a function address then execute it.
```
#include <unistd.h>
int main()
{
	void (*foo)();
	read(0, &foo, 8);
	foo();
}
```

Stop instruction at `call rdx`
![](https://imgur.com/fB8TyYk.jpg)

use `ogt -8` cause of call instruction
![](https://imgur.com/2TfiWcM.jpg)

0x10a38c constraints has been satisfied
![](https://imgur.com/QyQmEqy.jpg)

change the foo address and get shell
![](https://imgur.com/gGEIbpW.jpg)

## Reference
* [1] https://www-zeuthen.desy.de/unix/unixguide/infohtml/gdb/Python-API.html#Python-API
* [2] https://github.com/david942j/one_gadget
