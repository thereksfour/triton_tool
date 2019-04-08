import string

from triton  import *
from pintool import *

targetName = "serial.txt"
targetFd   = None
isOpen     = False
isRead     = None
INPUT = dict()
X86_MOV =[OPCODE.X86.MOV,OPCODE.X86.MOVZX]
MALLOCBUG = True


class Malloc():
    malloc_addr = 0
    malloc_size = 0
    state = ""


Malloc_list = []
Malloc_index = 0

Triton = getTritonContext()


def getNewInput():
    # Set of new inputs
    inputs = list()

    # Get path constraints from the last execution
    pco = Triton.getPathConstraints()

    # Get the astContext
    astCtxt = Triton.getAstContext()

    # We start with any input. T (Top)
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

    # Go through the path constraints
    for pc in pco:
        # If there is a condition
        if pc.isMultipleBranches():
            # Get all branches
            branches = pc.getBranchConstraints()
            for branch in branches:
                # Get the constraint of the branch which has been not taken
                if branch['isTaken'] == False and Triton.getConcreteMemoryAreaValue(branch['dstAddr'], 5)[-3:] != '\xfd\xff\xff':
                    # Ask for a model
                    #print "branch address %x"%(branch['srcAddr'])
                    models = Triton.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                    seed = dict()
                    for k, v in list(models.items()):
                        # Get the symbolic variable assigned to the model
                        symVar = Triton.getSymbolicVariableFromId(k)
                        # Save the new input as seed.
                        seed.update({symVar.getOrigin(): v.getValue()})
                    if seed:
                        inputs.append(seed)

        # Update the previous constraints with true branch to keep a good path.
        previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPathConstraintAst()])

    # Clear the path constraints to be clean at the next execution.
    Triton.clearPathConstraints()

    return inputs




def getMemoryString(addr):
    index = 0
    s = str()

    while getCurrentMemoryValue(addr+index):
        c = chr(getCurrentMemoryValue(addr+index))
        s += ("" if c not in string.printable else c)
        index += 1

    return s


def syscallsEntry(threadId, std):
    global isOpen
    global isRead
    global targetFd
    if getSyscallNumber(std) == SYSCALL64.OPENAT:
        name = getMemoryString(getSyscallArgument(std, 1))
        if name == targetName:
            isOpen = True
            #print('[TT] Target name match: %s' %(name))

    elif getSyscallNumber(std) == SYSCALL64.READ:
        fd   = getSyscallArgument(std, 0)
        buff = getSyscallArgument(std, 1)
        size = getSyscallArgument(std, 2)
        if fd == targetFd:
            isRead = {'buff': buff, 'size': size}

    return


def syscallsExit(threadId, std):
    global isOpen
    global isRead
    global targetFd

    if isOpen:
        targetFd = getSyscallReturn(std)
        isOpen = False
        #print('[TT] Target fd: %d' %(targetFd))

    elif isRead is not None:
        size = isRead['size']
        buff = isRead['buff']
        #Triton.concretizeAllRegister()
        #Triton.concretizeAllMemory()
        # for item in INPUT:
        #     for address, value in item.items():
        #         setCurrentMemoryValue(address, value)
        for address, value in INPUT.items():
            setCurrentMemoryValue(address, value)
            print('SET %x'%address, ' TO ',value)
        for index in range(size):
            Triton.taintMemory(buff+index)
            #print "Taint Mem: %x"%(buff+index)
            #Triton.setConcreteMemoryValue(buff+index, getCurrentMemoryValue(buff+index))
            Triton.convertMemoryToSymbolicVariable(MemoryAccess(buff+index, CPUSIZE.BYTE))
        isRead = None

    return


def fini():
    print 'finish'




def before(inst):
    if inst.getType() in X86_MOV:
        op = inst.getOperands()
        #print inst
        if op[1].getType() == OPERAND.MEM:
            #if Triton.isMemoryTainted(op[1]):
            readAddr = op[1].getAddress()
            #print "[Read] at %x" % readAddr
            for item in Malloc_list:
                if item.state == "free":
                    if readAddr >= item.malloc_addr and readAddr <= item.malloc_addr+item.malloc_size:
                        print "[UAF] In %x [%s]" % (readAddr,inst)

        if op[0].getType() == OPERAND.MEM:
            #if isMemoryTainted()
            #if Triton.isRegisterTainted(op[1]):
            #print "[Write] to %x" % op[0].getAddress()
            writeAddr = op[0].getAddress()
            for item in Malloc_list:
                if item.state == "free":
                    if writeAddr >= item.malloc_addr and writeAddr <= item.malloc_addr+item.malloc_size:
                        print "[UAF] In %x [%s]" % (writeAddr,inst)


def entry_main(threadId):
    print('[+] Take a snapshot')
    takeSnapshot()


lastInput = list()
worklist  = list()

def exit_main(threadId):
    global INPUT, lastInput, worklist
    #inputs = getNewInput()
    newInputs = getNewInput()
    for inputs in newInputs:
        if inputs not in lastInput and inputs not in worklist:
            worklist += [dict(inputs)]
    if worklist:
        seed = worklist[0]
        lastInput += [dict(seed)]
        del worklist[0]
        INPUT = seed
        print "INPUT",INPUT
        print('[+] Restore a snapshot')
        #disableSnapshot()
        restoreSnapshot()
    else:
        disableSnapshot()


def entry_malloc(threadId):
    global MALLOCBUG
    if MALLOCBUG:
        MALLOCBUG = False
        return
    global Malloc_index
    size = Triton.getConcreteRegisterValue(Triton.getRegister(REG.X86_64.EDI))
    malloc = Malloc()
    malloc.malloc_size = size
    Malloc_list.append(malloc)
    Malloc_index += 1



def exit_malloc(threadId):
    global Malloc_index, Malloc_list
    addr = Triton.getConcreteRegisterValue(Triton.getRegister(REG.X86_64.RAX))
    Malloc_list[Malloc_index-1].malloc_addr = addr
    Malloc_list[Malloc_index-1].state = "malloc"
    print "[malloc] at %x and size %x" % (addr, Malloc_list[Malloc_index-1].malloc_size)


def entry_free(threadId):
    addr = Triton.getConcreteRegisterValue(Triton.getRegister(REG.X86_64.RDI))
    for i in xrange(len(Malloc_list)):
        if Malloc_list[i].malloc_addr == addr:
            Malloc_list[i].state = "free"
    print "[free] at %x"%addr


if __name__ == '__main__':
    # Start the symbolic analysis from the Entry point
    startAnalysisFromEntry()
    #startAnalysisFromSymbol('main')
    setupImageBlacklist(["libc", "ld-linux"])
    insertCall(before, INSERT_POINT.BEFORE)
    insertCall(syscallsEntry, INSERT_POINT.SYSCALL_ENTRY)
    insertCall(syscallsExit,  INSERT_POINT.SYSCALL_EXIT)
    #insertCall(fini,          INSERT_POINT.FINI)
    insertCall(entry_main,INSERT_POINT.ROUTINE_ENTRY, 'main')
    insertCall(exit_main, INSERT_POINT.ROUTINE_EXIT, 'main')
    #insertCall(entry_open, INSERT_POINT.ROUTINE_ENTRY, 'open')
    #insertCall(exit_open, INSERT_POINT.ROUTINE_EXIT, 'open')

    insertCall(entry_malloc, INSERT_POINT.ROUTINE_ENTRY, 'malloc')
    insertCall(exit_malloc, INSERT_POINT.ROUTINE_EXIT, 'malloc')
    insertCall(entry_free, INSERT_POINT.ROUTINE_ENTRY, 'free')
    #insertCall(exit_free, INSERT_POINT.ROUTINE_EXIT, 'free')




    # Run the instrumentation - Never returns
    runProgram()
