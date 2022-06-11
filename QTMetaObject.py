# Try to rebuild the class from the QMetaObject information
#@author 
#@category QT
#@keybinding 
#@menupath 
#@toolbar
import logging
import struct
from ghidra.app.tablechooser import TableChooserExecutor, AddressableRowObject, StringColumnDisplay
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.data import (
    FunctionDefinitionDataType,
    GenericCallingConvention,
    IntegerDataType,
    ParameterDefinitionImpl,
    PointerDataType,
    VoidDataType,
    Enum,
)
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.database.data import EnumDB

import common


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


staticMetaObject = getSymbols('staticMetaObject', getNamespace(None, 'QObject'))[0]

"""
    enum Call {
        InvokeMetaMethod,
        ReadProperty,
        WriteProperty,
        ResetProperty,
        QueryPropertyDesignable,
        QueryPropertyScriptable,
        QueryPropertyStored,
        QueryPropertyEditable,
        QueryPropertyUser,
        CreateInstance,
        IndexOfMethod,
        RegisterPropertyMetaType,
        RegisterMethodArgumentMetaType
    };
"""

def get_staticMetaObject_DATA_refs():
    """Return all the DATA references to the QObject::staticMetaObject, probably they are
    the first entry of the QMetaObject struct."""

    return [_ for _ in getReferencesTo(staticMetaObject.getAddress()) if _.getReferenceType() == RefType.DATA]


class QMetaObject:
    """Wrap the static struct defining the QMetaObject and rebuild the
    class that it defines."""
    INT = getDataTypes('int')[0]
    HEADER_DATATYPE = getDataTypes('qt_meta_data_header_t')[0]

    HEADER_FIELD_CLASSNAME_INDEX = 1
    HEADER_FIELD_METHODS_COUNT_INDEX = 4
    HEADER_FIELD_METHODS_INDEX_INDEX = 5
    HEADER_FIELD_PROPS_COUNT_INDEX = 6
    HEADER_FIELD_PROPS_INDEX_INDEX = 7
    HEADER_FIELD_ENUMS_COUNT_INDEX = 8
    HEADER_FIELD_ENUMS_INDEX_INDEX = 9


    def __init__(self, address):
        self.address = address
        self.staticMetaObject = toAddr(getInt(address))
        self.stringdata = toAddr(getInt(address.add(4)))
        self.data = toAddr(getInt(address.add(8)))
        self.static_metacall = toAddr(getInt(address.add(12)))

        self.methods = {}  # this will contain the idx: method name

        # sanity check
        is_original_staticMetaObject = self.staticMetaObject == staticMetaObject.getAddress()

        if not is_original_staticMetaObject:
            symbol_at = getSymbolAt(self.staticMetaObject)

            if symbol_at is None:
                raise ValueError("Nothing is defined at {}: you should set the cursor at the start of a MetaObject vtable".format(self.staticMetaObject))

            if  "staticMetaObject" not in symbol_at.getName():
                logger.warning("you must have a cursor on a memory that references staticMetaObject instead of %s" % symbol_at)
            else:
                logger.info("this class derives from '%s'" % (symbol_at.getParentNamespace()))

        # obtain the info from the memory
        self.__build()

        # set the qt_metacast method as best as we can
        self.__configure_qt_metacast()

        # now find and set the correct signature for the signals
        self.find_signals()

    def get_size_int(self):
        """Make architecture independent the reading"""
        return self.INT.getLength()

    def __str__(self):
        return "%s %s #properties=%d #methods=%d" % (self.stringdata, self.data, self.properties_count, self.methods_count)

    def get_ghidra_class(self):
        """try to retrieve the class from the name and if doesn't exist create it."""
        # get the class (getObject() because otherwise is a symbol so not a Namespace)
        klass = currentProgram.getSymbolTable().getClassSymbol(self.class_name, None)

        if klass is None:
            logger.info("creating class '{}'".format(self.class_name))
            klass = currentProgram.symbolTable.createClass(None, self.class_name, SourceType.USER_DEFINED)
        else:
            klass = klass.getObject()

        logger.info("using class namespace '{}'".format(klass))

        return klass

    def __configure_qt_metacast(self):
        func_metacall = getFunctionAt(self.static_metacall)

        if func_metacall is None:
            logger.info("function not defined at {}, creating now".format(self.static_metacall))
            # use the "FUN_" prefix so that we change that after
            func_metacall = createFunction(self.static_metacall, "FUN_metacall")

        if not func_metacall.getName().startswith("FUN_"):
            logger.warning("manually edited function, do not change")
            return

        klass = self.get_ghidra_class()

        # now we are going to change Namespace, name and signature
        func_metacall.setParentNamespace(klass)
        func_metacall.setName("qt_metacast", SourceType.USER_DEFINED)

        sig = FunctionDefinitionDataType("miao")
        sig.setGenericCallingConvention(GenericCallingConvention.thiscall)

        datatype_call = getDataTypes('Call')[0]

        if type(datatype_call) != EnumDB:
            raise ValueError("The 'Call' datatype is not an Enum, please create it!")

        datatype_call = ParameterDefinitionImpl('call', datatype_call, 'type of call')
        datatype_index = ParameterDefinitionImpl('index', IntegerDataType.dataType, 'index of slots/methods/signal')
        datatype_args = ParameterDefinitionImpl('args', PointerDataType(PointerDataType(VoidDataType.dataType)), 'extra data')

        sig.setArguments([datatype_call, datatype_index, datatype_args])

        runCommand(ApplyFunctionSignatureCmd(func_metacall.entryPoint, sig, SourceType.USER_DEFINED))

    def __build_from_header(self):
        self.header = getDataAt(self.data)

        if self.header is None or self.header.getDataType() != self.HEADER_DATATYPE:
            self.header = createData(self.data, self.HEADER_DATATYPE)

        if self.header is None:
            raise ValueError("no data at %s" % self.data)

        self.class_name = self._get_qstring_at(
            self.header.getComponent(self.HEADER_FIELD_CLASSNAME_INDEX).value.getValue()).getString()

        logger.info("found class '%s'" % self.class_name)

        self.methods_count = self.header.getComponent(self.HEADER_FIELD_METHODS_COUNT_INDEX).value.getValue()
        self.methods_index = self.header.getComponent(self.HEADER_FIELD_METHODS_INDEX_INDEX).value.getValue()

        self.properties_count = self.header.getComponent(self.HEADER_FIELD_PROPS_COUNT_INDEX).value.getValue()
        self.properties_index = self.header.getComponent(self.HEADER_FIELD_PROPS_INDEX_INDEX).value.getValue()

        self.enums_count = self.header.getComponent(self.HEADER_FIELD_ENUMS_COUNT_INDEX).value.getValue()
        self.enums_index = self.header.getComponent(self.HEADER_FIELD_ENUMS_INDEX_INDEX).value.getValue()

        self.slots_index = self.header.getComponent(self.HEADER_FIELD_ENUMS_COUNT_INDEX).value.getValue()
        self.slots_count = self.header.getComponent(self.HEADER_FIELD_ENUMS_COUNT_INDEX).value.getValue()

    def _get_qstring_at(self, index):
        offset = QString.getHeaderSize() * index
        address = self.stringdata.add(offset)

        logger.debug("address for string: %s" % address)

        return QString(address)

    def _read_int(self, address):
        return getInt(address), address.add(self.get_size_int())

    def _read_uint(self, address):
        return struct.unpack("<I", getBytes(address, self.get_size_int()))[0], address.add(self.get_size_int())

    def __build_methods(self):
        return self.__build_attributes(self.methods_index, self.methods_count, "methods")

    def __build_slots(self):
        return self.__build_attributes(self.slots_index, self.slots_count, "slots")

    def __build_attributes(self, index, count, description):
        address = self.data.add(self.get_size_int() * index)

        logger.info("looking for %s at %s" % (description, address))

        methods = []

        for idx in range(count):
            name, address = self._read_int(address)
            attr_name = self._get_qstring_at(name).getString()
            print idx, attr_name, "(",

            # n parameters
            argc, address = self._read_int(address)
            parameters, address = self._read_int(address)
            tag, address = self._read_int(address)
            flags, address = self._read_int(address)

            address_param = self.data.add(self.get_size_int() * parameters)
            param, address_param = self._read_int(address_param)

            print "return=", param,

            for pidx in range(argc):
                #address_param = self.data.add(self.get_size_int() * parameters)
                param, address_param = self._read_uint(address_param)
                param_name_idx, address_param = self._read_uint(address_param)
                param_name = self._get_qstring_at(param_name_idx & 0x7fffffff)
                print hex(param), hex(param_name_idx), param_name, ",",

            print ")"

            methods.append((name, argc, parameters, tag, flags))

            attr = getattr(self, description)
            attr[idx] = attr_name

        logger.debug(methods)

    def __build_properties(self):
        address = self.data.add(self.get_size_int() * self.properties_index)

        logger.info("looking for properties at %s" % address)

        properties = []

        for idx in range(self.properties_count):
            name, address = self._read_int(address)

            print idx, self._get_qstring_at(name),

            type, address = self._read_uint(address)

            value_type = type & 0x7fffffff

            print value_type,

            if type & 0x80000000:
                print "unresolved: ", self._get_qstring_at(value_type)
            else:
                print

            flags, address = self._read_int(address)

            properties.append((name, type, hex(flags)))

        logger.debug("properties:", properties)

    def __build_enums(self):
        address = self.data.add(self.get_size_int() * self.enums_index)

        logger.info("looking for enums at %s" % address)

        enums = []

        for idx in range(self.enums_count):
            name, address = self._read_int(address)

            print idx, self._get_qstring_at(name)

            alias, address = self._read_int(address)
            flags, address = self._read_int(address)
            count, address = self._read_int(address)
            data, address = self._read_int(address)

            enums.append((name, alias, flags, count, data))

        logger.debug(enums)

        for _, _, _, count, _ in enums:
            for idx in range(count):
                name, address = self._read_int(address)

                print idx, self._get_qstring_at(name),

                value, address = self._read_int(address)

                print value

    def __build(self):
        # start from the header
        self.__build_from_header()
        self.__build_methods()
        self.__build_properties()
        self.__build_enums()

    def _show_undefined_functions(self, addresses):
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
                return self.row

        tableDialog = createTableChooserDialog("Undefined functions", ArgumentsExecutor(), False)

        for address in addresses:
            # check that there is no data there
            data = getDataAt(address)
            if data:
                logger.info("found data {} at {}".format(data, address))
                continue
            tableDialog.add(Argument(address))

        if tableDialog.getRowCount() > 0:
            tableDialog.show()

    def find_signals(self):
        """The idea here is that QMetaObject::activate() with our MetaObject vtable
        will identify all the signals of this object."""
        activate = common.get_function_by_name('activate', namespace='QMetaObject')

        xrefs_activate = set(common.getXref(activate))

        xrefs_metavtable = common.get_functions_via_xref(self.address)

        undefined = filter(lambda _: _[1] is None, xrefs_metavtable)

        logger.info("TODO: table for {}".format(undefined))

        import collections

        xrefs_metavtable_counted = collections.Counter([_[1] for _ in xrefs_metavtable])

        xrefs_metavtable = set([func for func, count in xrefs_metavtable_counted.items() if count == 1])
        # TODO: create table with undefined functions
        # take only the xrefs with one single

        logger.debug(xrefs_metavtable_counted)

        klass = self.get_ghidra_class()

        if undefined:
            self._show_undefined_functions([_[0] for _ in undefined])

        for xref in xrefs_metavtable & xrefs_activate:
            if xref is None:
                continue

            """Now the logic to follow would be
            
            1. it's the unique call inside that function
            2. the first parameter is a function parameter
            """
            for caller in common.getCallerInfo(activate, xref):
                logger.debug(xref)
                logger.debug(caller)
                signal_name = self.methods[caller[3]]

                logger.info("found signal: '{}'".format(signal_name))

                xref.setParentNamespace(klass)
                xref.setCallingConvention('__thiscall')

                if not xref.getName().startswith("FUN_"):
                    logger.warning("not changing function name since it seems user generated")
                    continue

                logger.info("renaming {} -> {}".format(xref.getName(), signal_name))

                xref.setName(signal_name, SourceType.USER_DEFINED)


class QString:
    DATATYPE = getDataTypes('QArrayData')[0]

    def __init__(self, address):
        # createData(address, )
        data = getDataAt(address)

        if data is None:
            data = createData(address, self.DATATYPE)

        if data.getDataType() != self.DATATYPE:
            raise ValueError("No data defined at %s" % address)

        self.object = data

    @classmethod
    def getHeaderSize(cls):
        return cls.DATATYPE.getLength()

    def getString(self):
        address_string = self.object.getAddress().add(self.object.getComponent(3).value.getValue())
        data = getDataAt(address_string)

        if data is None:
            data = createData(address_string, getDataTypes('string')[0])

        return data.value

    def __str__(self):
        return self.getString()

obj = QMetaObject(currentAddress)

print obj
