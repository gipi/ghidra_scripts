# The idea here is to build a data type to use as a "container" for
# the virtual table of a given class. Select the region with the
# pointers to the virtual functions, having as a constraint that a
# label of the form "<Class>::vtable" is at the start of it.
#@author Gianluca Pacchiella
#@category QT
#@keybinding SHIFT-V
#@menupath 
#@toolbar
import logging

from ghidra.program.model.data import (
    StructureDataType,
    IntegerDataType,
    DataTypeConflictHandler,
    PointerDataType,
    FunctionDefinitionDataType,
)

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


def build_structure(class_name, startAddress, count):
    path = "{}_vtable_t".format(class_name)
    logger.info("building struct named {}".format(path))
    structure = StructureDataType(path, 0)

    for index in range(count):
        logger.debug(" index: {}".format(index))
        address = startAddress.add(index * 4)
        addr_func = toAddr(getDataAt(address).getInt(0))
        function = getFunctionAt(addr_func)

        if function is None:
            logger.info("no function at {}, creating right now!".format(address))
            function = createFunction(addr_func, None)  # use default name

        function_name = function.getName()

        # if it's a function with an already defined Namespace don't change that
        if function.getParentNamespace().isGlobal():
            # set the right Namespace and the __thiscall convention
            namespace = getNamespace(None, class_name)
            function.setParentNamespace(namespace)

        function.setCallingConvention('__thiscall')
        funcDefinition = FunctionDefinitionDataType(function, False)

        logger.debug(" with signature: {}".format(funcDefinition))

        ptr_func_definition_data_type = PointerDataType(funcDefinition)

        # we are going to save definition and all
        # but probably we should clean the old definitions
        # of data types?
        data_type_manager = currentProgram.getDataTypeManager()
        logger.debug("Replacing {}".format(funcDefinition))
        # we replace all the things since they are generated automagically anyway
        data_type_manager.addDataType(funcDefinition, DataTypeConflictHandler.REPLACE_HANDLER)
        data_type_manager.addDataType(ptr_func_definition_data_type, DataTypeConflictHandler.REPLACE_HANDLER)

        structure.insertAtOffset(  # FIXME: in general 4 is not the right size
            index * 4,
            ptr_func_definition_data_type,
            4,
            function_name,
            "",
        )

    return structure


def set_vtable_datatype(class_name, structure):
    path = "/{}".format(class_name)
    class_type = currentProgram.getDataTypeManager().getDataType(path)

    if class_type is None or class_type.isZeroLength():
        raise ValueError("You must define the class '{}' with '_vtable' before".format(class_name))

    field = class_type.getComponent(0)
    field_name = field.getFieldName()

    if field_name != "_vtable":
        raise ValueError("I was expecting the first field to be named '_vtable'")

    logger.info("set vtable as a pointer to {}".format(structure.getName()))
    field.setDataType(PointerDataType(structure))


def main():
    startAddress = currentSelection.getFirstRange().getMinAddress()
    count = currentSelection.getFirstRange().getLength() / 4

    sym = getSymbolAt(startAddress)

    if sym is None or sym.getName() != "vtable" or sym.isGlobal():
        raise ValueError(
            "I was expecting a label here indicating the class Namespace, something like 'ClassName::vtable'")

    # FIXME: nested namespaces are not handled correctly
    class_name = sym.getParentNamespace().getName()
    if "::" in class_name:
        raise ValueError("Probably you want to handle manually this one: namespace '{}'".format(class_name))

    structure = build_structure(class_name, startAddress, count)

    data_type_manager = currentProgram.getDataTypeManager()
    logger.info("Replacing {}".format(structure.getName()))
    data_type_manager.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER)

    set_vtable_datatype(class_name, structure)

main()
