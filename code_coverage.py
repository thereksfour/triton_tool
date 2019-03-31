import string
import sys
import time

from triton  import *
from pintool import *

targetName = "serial.txt"
targetFd   = None
isOpen     = False
isRead     = None
INPUT = dict()
TIME = 0

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
                if branch['isTaken'] == False and Triton.getConcreteMemoryAreaValue(branch['dstAddr'], 5) != '\xe8\xe5\xfd\xff\xff':
                    # Ask for a model
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
            print('SET ', address, ' TO ',value)
        for index in range(size):
            Triton.taintMemory(buff+index)
            #Triton.setConcreteMemoryValue(buff+index, getCurrentMemoryValue(buff+index))
            Triton.convertMemoryToSymbolicVariable(MemoryAccess(buff+index, CPUSIZE.BYTE))
        isRead = None

    return


def fini():
    print 'finish'


def before(inst):
    pass
    #print inst
    #print type(inst.getNextAddress())
    #print getRoutineName(inst.getNextAddress())
    #print type(inst.getAddress())


def entry_main(threadId):
    print('[+] Take a snapshot')
    takeSnapshot()


lastInput = list()
worklist  = list([{0:0}])

def exit_main(threadId):
    global TIME, INPUT, lastInput, worklist
    #inputs = getNewInput()
    if worklist:
        seed = worklist[0]
        lastInput += [dict(seed)]
        del worklist[0]

        newInputs = getNewInput()
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]
        if seed == {0:0}:
            pass
        else:
            INPUT = seed
        print 'INPUT: ',INPUT
        print('[+] Restore a snapshot')
        restoreSnapshot()
    else:
        disableSnapshot()


if __name__ == '__main__':
    # Start the symbolic analysis from the Entry point
    startAnalysisFromEntry()
    #startAnalysisFromSymbol('main')
    setupImageBlacklist(["libc", "ld-linux"])
    #insertCall(before, INSERT_POINT.BEFORE)
    insertCall(syscallsEntry, INSERT_POINT.SYSCALL_ENTRY)
    insertCall(syscallsExit,  INSERT_POINT.SYSCALL_EXIT)
    insertCall(fini,          INSERT_POINT.FINI)
    insertCall(entry_main,INSERT_POINT.ROUTINE_ENTRY,'main')
    insertCall(exit_main, INSERT_POINT.ROUTINE_EXIT, 'main')

    # Run the instrumentation - Never returns
    runProgram()
