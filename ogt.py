import gdb
import subprocess

reg = ('rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'eflags')
operator = ('+', '-', '*', '/', '%', '==', '&', '|', '^', '||')

class ogt(gdb.Command):
    "use ogt do check if there has any one gagdet instruction can sufficient constraints"
    def __init__(self):
        super(self.__class__, self).__init__("ogt", gdb.COMMAND_USER)
        self.libc_path = ''
        self.constraints = {}
        self.rsp_fix = 0
        self.inferior = None
        self.frame = None

    def invoke(self, args, from_tty):
        if self.inferior is None:
            try:
                self.inferior = gdb.selected_inferior()
            except RuntimeError:
                return

            if not self.inferior or not self.inferior.is_valid():
                return

        # user may use ogt in different frame, so update everytime when
        # user execute command
        try:
            self.frame = gdb.selected_frame()
        except RuntimeError:
            return 

        if not self.frame or not self.frame.is_valid():
            return

        if len(args)>  1:
            self.rsp_fix = int(args)
        try:
            self.__get_libc_path();
        except:
            print("Get libc path error, you might need to specific by yourself")

        # use one_gagdet tool to find one gadget in current libc
        out = subprocess.check_output(["one_gadget", self.libc_path])
        outputstr = out.decode('ascii')
        self.__parse_constraints(outputstr)
        self.__check_expression() 

    def __get_libc_path(self):
        if self.libc_path is not '':
            return
        pid = gdb.execute("getpid", False, True)
        filename = "/proc/" + pid[:-1] + "/maps"
        with open(filename, "r") as f:
            for ln in f:
                # find libc path
                if ln.find("libc") is not -1 and ln.find("r-x") is not -1:
                    self.libc_path = ln[ln.find('/'):-1]


    def __parse_constraints(self, outputstr):
        # parse one line by one line
        lnlist = outputstr.split('\n')
        key = 0
        constraints = []
        for ln in lnlist:
            # fine one gagdet address
            if ln.find('execve') is not -1:
                # put last key: value in dictionary
                if key is not 0:
                    self.constraints[key] = constraints
                key = int(ln[:ln.find(' ')], 16)
                # flush constraints
                constraints = []
            if ln.find('==') is not -1:
                constraints.append(ln[2:])

        self.constraints[key] = constraints

    def __check_expression(self):
        for og in self.constraints:
            print("Address \033[38;5;189m" + hex(og) + "\033[0m:")
            explist = self.constraints.get(og)
            flag = False
            for exp in explist:
                flag = self.__emulate_exp(exp)
                if flag is False:
                    print("\033[91m" + exp + "\033[0m")
                else:
                    print("\033[92m" + exp + "\033[0m")


    def __emulate_exp(self, exp):
        if type(exp) is str:
            exp = exp.split(' ')
        instance = []
        for op in exp:
            if op in reg:
                value = self.frame.read_register(op)
                value = int(value)
                if op == 'rsp':
                    value += self.rsp_fix
                instance.append(hex(value))
            elif op in operator or op.startswith('0'):
                instance.append(op)
            elif op == 'NULL':
                instance.append('0')
            elif op[0] == '[':
                # seperate all the operator by hand...
                op = op[1:-1]
                # double dereference
                # basically next procedure will take care of this case
                if op[0] == '[':
                    op = hex(self.__emulate_exp(op))
                else:
                    subexp = []
                    for i in range(len(op)):
                        j = i
                        while op[i:j] not in reg and op[i:j] not in operator and op[i] != 0 and j <= len(op):
                            j += 1
                        else:
                            if j <= len(op) or op[i:].startswith('0x'):
                                subexp.append(op[i:j])
                # dereference address
                addr = self.__emulate_exp(subexp)
                value = self.inferior.read_memory(addr, 8).tobytes()
                instance.append(hex(int.from_bytes(value, byteorder='little')))
        # eval('exp || exp') will get false
        while '||' in instance:
            instance[instance.index('||')] = 'or'
        while '&&' in instance:
            instance[instance.index('&&')] = 'and'
        eval_args = ''.join(i + ' ' for i in instance)
        return eval(eval_args)
ogt()
