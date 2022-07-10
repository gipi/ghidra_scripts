# List qmlregister() arguments
#@author 
#@category QT
#@keybinding 
#@menupath 
#@toolbar
import re
from collections import deque
import logging

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.tablechooser import TableChooserExecutor, AddressableRowObject, StringColumnDisplay
from ghidra.program.model.pcode import HighLocal, VarnodeAST, Varnode, PcodeOpAST, HighSymbol, PcodeOp
from ghidra.program.database.function import LocalVariableDB
# https://reverseengineering.stackexchange.com/questions/25322/extracting-info-from-ghidra-listing-window
from ghidra.program.model.listing import CodeUnitFormat, CodeUnitFormatOptions

import common

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


FUNC_NAME = 'qmlregister'

# from qtdeclarative/src/qml/qml/qqmlprivate.h
REGISTRATION_TYPE_DECLARATION = """
enum
RegistrationType
{
    TypeRegistration = 0,
    InterfaceRegistration = 1,
    AutoParentRegistration = 2,
    SingletonRegistration = 3,
    CompositeRegistration = 4,
    CompositeSingletonRegistration = 5,
    QmlUnitCacheHookRegistration = 6,
    TypeAndRevisionsRegistration = 7,
    SingletonAndRevisionsRegistration = 8
};
"""


# set the formatting output for the listing
# so that we can extract information from it
codeUnitFormat = CodeUnitFormat(
    CodeUnitFormatOptions(
        CodeUnitFormatOptions.ShowBlockName.ALWAYS,
        CodeUnitFormatOptions.ShowNamespace.ALWAYS,
        "",
        True,
        True,
        True,
        True,
        True,
        True,
        True)
)

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
    print "get_stack_var_from_varnode():", varnode, type(varnode)
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
    print "get_get_vars_from_varnode():", node, type(node)
    if type(node) not in [PcodeOpAST, VarnodeAST]:
        raise Exception("Invalid value passed. Got {}.".format(type(node)))

    # create `variables` list on first call. Do not make `variables` default to [].
    if variables == None:
        variables = []

    # We must use `getDef()` on VarnodeASTs
    if type(node) == VarnodeAST:
        print " from addr:", node.getPCAddress()
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
        print " from addr:", node.getSeqnum()
        nodes = list(node.getInputs())
        for node in nodes:
            if type(node.getHigh()) == HighLocal:
                variables.append(node.getHigh())
            else:
                variables = get_vars_from_varnode(func, node, variables)
    return variables


"""
The table code is inspired from here <https://github.com/v-p-b/rabbithole/blob/6fa2f24b091ccfce4f6617c9b5db367445ef2a7c/rabbithole.py>
"""
class ArgumentsExecutor(TableChooserExecutor):
    def execute(self, rowObject):
        return True

    def getButtonName(self):
        return "I'm late!"


class Argument(AddressableRowObject):
    def __init__(self, row):
        # using "address" raises "AttributeError: read-only attr: address"
        self.row = row

    def getAddress(self):
        return self.row[0]


class TypeColumn(StringColumnDisplay):
    def getColumnName(self):
        return u"Type"

    def getColumnValue(self, row):
        return row.row[1]


class ClassNameColumn(StringColumnDisplay):
    def getColumnName(self):
        return u"Class"

    def getColumnValue(self, row):
        return row.row[2]


def getXref(func):
    target_addr = func.entryPoint
    references = getReferencesTo(target_addr)
    callers = []
    for xref in references:
        call_addr = xref.getFromAddress()
        caller = getFunctionContaining(call_addr)
        callers.append(caller)
    return list(set(callers))




def getSymbolFromAnnotation(annotation):
    """The label referenced from an instruction is something like

     prefix_address+offset
    """
    match = re.match(r"(.+?) (r.+)=>(.+?):(.+?),\[sp,", annotation)

    if not match:
        print "annotation failed:", annotation
        return None

    match = match.group(4)

    try:
        offset_plus = match.index("+")
    except ValueError:
        return getSymbol(match, None)

    return None


def getCallerInfo(func, caller, options = DecompileOptions(), ifc = DecompInterface()):
    print("function: '%s'" % caller.name)

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

    results = []

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

                    print("Call to {} at {} has {} arguments: {}".format(addr, source_addr, len(args), args))

                    for pos, arg in enumerate(args):
                        # var = arg.getHigh()
                        # print "var", var, var.getSymbol(), var.getDataType()
                        # print "lsm", lsm.findLocal(arg.getAddress(), None)

                        if pos != 0:
                            print "initial arg%d: %s" % (pos, arg)
                            refined = get_vars_from_varnode(caller, arg)

                            if len(refined) > 0:
                                refined = refined[0]
                                print "found variable '%s' for arg%d" % (refined, pos)
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
                                print "symbol from annotations", from_annotation

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

                            print("arg%d: %08x" % (pos, arg.getAddress().getOffset()))
                        else:
                            print("arg0: %d" % int(arg.getAddress().getOffset()))

                        calling_args[pos] = arg.getAddress().getOffset()

                    calling_args.insert(0, source_addr)

                    # remember:  it's possible we have more than one call to the same function
                    results.append(calling_args)

        return results


datatype_registerSingletonType = getDataTypes('RegisterSingletonType')
if len(datatype_registerSingletonType) > 1:
    raise ValueError("You must have only one RegisterSingletonType data type")

datatype_registerSingletonType = datatype_registerSingletonType[0]

def get_string_from_stack(variable, source_addr):
    """Try to extract the string pointed by the struct on the struct"""
    if type(variable) != LocalVariableDB:
        logger.warning("variable {} from {} is not a local variable, nothing to do here".format(variable, source_addr))
        return None

    if variable.getDataType() != datatype_registerSingletonType:
        logger.warning("variable {} from {} is not a RegisterSingletonType but {}, nothing to do here".format(
            variable, source_addr, variable.getDataType()))
        return None

    if not variable.isStackVariable():
        logger.warning("variable {} from {} is not a stack variable, nothing to do here".format(variable, source_addr))
        return None

    ref_mgr = currentProgram.getReferenceManager()
    offset_field = variable.getStackOffset() + variable.getDataType().getComponent(4).getOffset()
    # print "offset_field", offset_field
    refs = sorted([(_.getFromAddress().getOffset(), _)
                   for _ in ref_mgr.getReferencesTo(variable)
                   if _.getFromAddress() < source_addr
                   and _.getStackOffset() == offset_field],
                  key=lambda _: _[0])[-1]

    instr = getInstructionAt(refs[1].getFromAddress())
    # print "op before", refs, refs[1]
    # print "instr:", instr, instr.getPcode(), instr.getDefaultOperandRepresentation(0)
    annotation = codeUnitFormat.getRepresentationString(instr)
    # print "annotation", annotation
    from_annotation = getSymbolFromAnnotation(annotation)
    print "symbol from annotations", from_annotation

    rX = instr.getRegister(0)

    # print "instr+reg", rX, instr.getInstructionContext().getRegisterValue(rX)

    pcode = instr.getPcode()[1]

    # print "pcode:", pcode, pcode.getSeqnum().getTarget()

    if pcode.getOpcode() != PcodeOp.STORE:
        raise ValueError("I was expecting a STORE operation here")

    value = pcode.getInput(1)

    # print "value", value, value.getAddress(), value.getDef(), value.getDescendants()

    # c_line = getCLine(markup, pcode.getSeqnum().getTarget())
    # print "C code", c_line

    output = getDataAt(from_annotation.getAddress()) if from_annotation else None

    return output


def get_function_by_name(name):
    """Little hacky way of finding the function by name since getFunction() by FlatAPI
    doesn't work."""
    candidates = [_ for _ in currentProgram.getFunctionManager().getFunctionsNoStubs(True) if name == _.name]

    if len(candidates) > 1:
        raise ValueError("We expected to find only one of '%s'" % name)

    return candidates[0]







def check():
    """Check that the data types we are supposed to use exist"""
    RegisterSingletonType = getDataTypes('RegisterSingletonType')[0]

    if RegisterSingletonType is None:
        print "creating 'RegisterSingletonType'"

    check_and_create('RegistrationType', REGISTRATION_TYPE_DECLARATION)


def main():
    check()
    QMLREGISTER = get_function_by_name(FUNC_NAME)
    print "Found '%s' at %s" % (FUNC_NAME, QMLREGISTER.entryPoint)

    tableDialog = createTableChooserDialog("qmlregister() calls", ArgumentsExecutor(), False)
    tableDialog.addCustomColumn(TypeColumn())
    tableDialog.addCustomColumn(ClassNameColumn())

    results = []

    for caller in getXref(QMLREGISTER):
        if caller is None:
            continue
        results.extend(common.getCallerInfo(QMLREGISTER, caller))

    for addr_source, registrationType, var_struct in results:
        klass_name = get_string_from_stack(var_struct, addr_source)
        tableDialog.add(Argument([addr_source, registrationType, klass_name]))

    tableDialog.show()

main()