import logging

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import HighLocal, VarnodeAST, Varnode, PcodeOpAST, HighSymbol, PcodeOp

# this below allows to have the global objects as in the scripts themself
# see <https://github.com/NationalSecurityAgency/ghidra/issues/1919>
from __main__ import *

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


def get_function_by_name(name):
    """Little hacky way of finding the function by name since getFunction() by FlatAPI
    doesn't work."""
    candidates = [_ for _ in currentProgram.getFunctionManager().getFunctionsNoStubs(True) if name == _.name]

    if len(candidates) > 1:
        raise ValueError("We expected to find only one of '%s'" % name)

    return candidates[0]

def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    # Setting a simplification style will strip useful `indirect` information.
    # Please don't use this unless you know why you're using it.
    #ifc.setSimplificationStyle("normalize")
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def get_stack_var_from_varnode(func, varnode):
    logger.debug("get_stack_var_from_varnode():", varnode, type(varnode))
    if type(varnode) not in [Varnode, VarnodeAST]:
        raise Exception("Invalid value. Expected `Varnode` or `VarnodeAST`, got {}.".format(type(varnode)))

    bitness_masks = {
        '16': 0xffff,
        '32': 0xffffffff,
        '64': 0xffffffffffffffff,
    }

    try:
        addr_size = currentProgram.getMetadata()['Address Size']
        bitmask = bitness_masks[addr_size]
    except KeyError:
        raise Exception("Unsupported bitness: {}. Add a bit mask for this target.".format(addr_size))

    local_variables = func.getAllVariables()
    vndef = varnode.getDef()
    if vndef:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset() & bitmask
            for lv in local_variables:
                unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
                if unsigned_lv_offset == defop_input_offset:
                    return lv

        # If we get here, varnode is likely a "acStack##" variable.
        hf = get_high_function(func)
        lsm = hf.getLocalSymbolMap()
        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
            for symbol in lsm.getSymbols():
                if symbol.isParameter():
                    continue
                if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                    return symbol

    # unable to resolve stack variable for given varnode
    return None


def get_vars_from_varnode(func, node, variables=None):
    logger.debug("get_get_vars_from_varnode():", node, type(node))
    if type(node) not in [PcodeOpAST, VarnodeAST]:
        raise Exception("Invalid value passed. Got {}.".format(type(node)))

    # create `variables` list on first call. Do not make `variables` default to [].
    if variables == None:
        variables = []

    # We must use `getDef()` on VarnodeASTs
    if type(node) == VarnodeAST:
        logger.debug(" from addr:", node.getPCAddress())
        # For `get_stack_var_from_varnode` see:
        # https://github.com/HackOvert/GhidraSnippets
        # Ctrl-F for "get_stack_var_from_varnode"
        var = get_stack_var_from_varnode(func, node)
        if var and type(var) != HighSymbol:
            variables.append(var)
        node = node.getDef()
        if node:
            variables = get_vars_from_varnode(func, node, variables)
    # We must call `getInputs()` on PcodeOpASTs
    elif type(node) == PcodeOpAST:
        logger.debug(" from addr:", node.getSeqnum())
        nodes = list(node.getInputs())
        for node in nodes:
            if type(node.getHigh()) == HighLocal:
                variables.append(node.getHigh())
            else:
                variables = get_vars_from_varnode(func, node, variables)
    return variables

def getXref(func):
    target_addr = func.entryPoint
    references = getReferencesTo(target_addr)
    callers = []
    for xref in references:
        call_addr = xref.getFromAddress()
        caller = getFunctionContaining(call_addr)
        callers.append(caller)
    return list(set(callers))

def getCallerInfo(func, caller, options = DecompileOptions(), ifc = DecompInterface()):
    logger.info("function: '%s'" % caller.name)

    target_addr = func.entryPoint

    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    # prog_ctx = currentProgram.getProgramContext()

    monitor = ConsoleTaskMonitor()
    res = ifc.decompileFunction(caller, 60, monitor)
    high_func = res.getHighFunction()
    lsm = high_func.getLocalSymbolMap()
    markup = res.getCCodeMarkup()

    symbols = lsm.getSymbols()
    stack_frame = caller.getStackFrame()
    ref_mgr = currentProgram.getReferenceManager()

    if high_func:
        opiter = high_func.getPcodeOps()

        while opiter.hasNext():
            op = opiter.next()
            mnemonic = str(op.getMnemonic())
            if mnemonic == "CALL":
                inputs = op.getInputs()

                # we are going to save the argument of the requested call
                # but we are not interested to the address that is the inputs[0]
                # argument from the PcodeOp
                calling_args = [0] * (len(inputs) - 1)

                addr = inputs[0].getAddress()
                args = inputs[1:] # List of VarnodeAST types

                if addr == target_addr:
                    source_addr = op.getSeqnum().getTarget()

                    logger.info("Call to {} at {} has {} arguments: {}".format(addr, source_addr, len(args), args))

                    for pos, arg in enumerate(args):
                        # var = arg.getHigh()
                        # print "var", var, var.getSymbol(), var.getDataType()
                        # print "lsm", lsm.findLocal(arg.getAddress(), None)

                        if pos != 0:
                            logger.debug("initial arg%d: %s" % (pos, arg))
                            refined = get_vars_from_varnode(caller, arg)

                            if len(refined) > 0:
                                refined = refined[0]
                                logger.debug("found variable '%s' for arg%d" % (refined, pos))
                                # print refined, type(refined)
                                """

                                print "symbol", refined.getSymbol(), refined.getSymbol().getAddress(), dir(refined.getSymbol()), refined.getSymbol().getSymbolType()
                                print "address", refined.getLastStorageVarnode().getAddress()
                                print "high", refined.getLastStorageVarnode().getHigh()
                                # print "getDef()", refined.getDef()
                                print "last", refined.getFirstStorageVarnode().getDef()
                                print "stack", stack_frame.getVariableContaining(refined.getStackOffset())
                                print "references", '\n'.join([str(_) for _ in ref_mgr.getReferencesTo(refined)])
                                """
                                # print "auaua", [(_.getFromAddress().getOffset(), _.getStackOffset()) for _ in ref_mgr.getReferencesTo(refined) if
                                #      _.getFromAddress() < source_addr]
                                # here we are going to create an ordered list with all the references to the given variable
                                # that happen before the call and return only the last one that hopefully is the one
                                # setting the value
                                # Bad enough this is a struct so the variable points to the start address of the struct
                                # if you want a specific field you have to add its offset
                                offset_field = refined.getStackOffset() + refined.getDataType().getComponent(4).getOffset()
                                # print "offset_field", offset_field
                                refs = sorted([(_.getFromAddress().getOffset(), _)
                                               for _ in ref_mgr.getReferencesTo(refined)
                                               if _.getFromAddress() < source_addr
                                                and _.getStackOffset() == offset_field],
                                              key = lambda _ : _[0])[-1]

                                instr = getInstructionAt(refs[1].getFromAddress())
                                #print "op before", refs, refs[1]
                                #print "instr:", instr, instr.getPcode(), instr.getDefaultOperandRepresentation(0)
                                annotation = codeUnitFormat.getRepresentationString(instr)
                                # print "annotation", annotation
                                from_annotation = getSymbolFromAnnotation(annotation)
                                logger.debug("symbol from annotations", from_annotation)

                                rX = instr.getRegister(0)

                                # print "instr+reg", rX, instr.getInstructionContext().getRegisterValue(rX)

                                pcode = instr.getPcode()[1]

                                # print "pcode:", pcode, pcode.getSeqnum().getTarget()

                                if pcode.getOpcode() != PcodeOp.STORE:
                                    raise ValueError("I was expecting a STORE operation here")

                                value = pcode.getInput(1)

                                # print "value", value, value.getAddress(), value.getDef(), value.getDescendants()

                                #c_line = getCLine(markup, pcode.getSeqnum().getTarget())
                                #print "C code", c_line

                                output = getDataAt(from_annotation.getAddress()) if from_annotation else None

                                calling_args[pos] = output


                                continue  # we exit since our job is finished
                            while arg.getDef().getOpcode() == PcodeOp.CAST:
                                arg = arg.getDef().getInput(0)

                            # OK, this is a little weird, but PTRSUBs with first arg == 0
                            # are (usually) global variables at address == second arg
                            if arg.getDef().getOpcode() == PcodeOp.PTRSUB:
                                arg = arg.getDef().getInput(1)
                            elif arg.getDef().getOpcode() == PcodeOp.COPY:
                                arg = arg.getDef().getInput(0)
                            else:
                                raise ValueError("I was not expection that")

                            logger.debug("arg%d: %08x" % (pos, arg.getAddress().getOffset()))
                        else:
                            logger.debug("arg0: %d" % int(arg.getAddress().getOffset()))

                        calling_args[pos] = arg.getAddress().getOffset()

                    calling_args.insert(0, source_addr)

                    # remember:  it's possible we have more than one call to the same function
                    logger.info(calling_args)
                    yield calling_args

