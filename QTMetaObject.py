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
    StructureDataType,
    FunctionDefinitionDataType,
    GenericCallingConvention,
    IntegerDataType,
    ParameterDefinitionImpl,
    PointerDataType,
    VoidDataType,
    EnumDataType,
    DataTypeConflictHandler,
)

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.database.data import EnumDB

import common
from QString import QString

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


def create():
    name = "qt_meta_data_header_t"
    metadata = StructureDataType(name, 0)

    metadata.add(
        IntegerDataType.dataType,
        0,
        "revision",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "className",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "classInfo_count",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "classInfo_index",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "methods_count",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "methods_index",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "properties_count",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "properties_index",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "enum_count",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "enum_index",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "constructor_count",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "constructor_index",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "flags",
        "",
    )
    metadata.add(
        IntegerDataType.dataType,
        0,
        "signal_count",
        "",
    )

    currentProgram.getDataTypeManager().addDataType(metadata, DataTypeConflictHandler.REPLACE_HANDLER)

    # you need to requery; since it has no category indicated you should obtain the first one
    return getDataTypes(name)[0]


def get():
    qt_meta_data_header = getDataTypes('qt_meta_data_header_t')

    if len(qt_meta_data_header) == 0 or qt_meta_data_header[0].isNotYetDefined():
        return create(), True

    return qt_meta_data_header[0], False


staticMetaObject = getSymbols('staticMetaObject', getNamespace(None, 'QObject'))[0]


def get_Call_enum():
    datatype_call = getDataTypes('Call')[0]

    # minimal check
    if type(datatype_call) == EnumDB and datatype_call.getCount() == 13:
        return datatype_call


    # otherwise we can create it
    entries = [
        "InvokeMetaMethod",
        "ReadProperty",
        "WriteProperty",
        "ResetProperty",
        "QueryPropertyDesignable",
        "QueryPropertyScriptable",
        "QueryPropertyStored",
        "QueryPropertyEditable",
        "QueryPropertyUser",
        "CreateInstance",
        "IndexOfMethod",
        "RegisterPropertyMetaType",
        "RegisterMethodArgumentMetaType",
    ]
    call = EnumDataType("Call", 1)

    for idx, name in enumerate(entries):
        call.add(name, idx)

    data_type_manager = currentProgram.getDataTypeManager()
    data_type_manager.addDataType(call, DataTypeConflictHandler.DEFAULT_HANDLER)

    # requery
    return getDataTypes('Call')[0]


def get_staticMetaObject_DATA_refs():
    """Return all the DATA references to the QObject::staticMetaObject, probably they are
    the first entry of the QMetaObject struct."""

    return [_ for _ in getReferencesTo(staticMetaObject.getAddress()) if _.getReferenceType() == RefType.DATA]


class QMetaObject:
    """Wrap the static struct defining the QMetaObject and rebuild the
    class that it defines.

    It's originally defined like the following:

        static const uint qt_meta_data_Counter[] = {

         // content:
               7,       // revision
               0,       // classname
               0,    0, // classinfo
               2,   14, // methods
               0,    0, // properties
               0,    0, // enums/sets
               0,    0, // constructors
               0,       // flags
               1,       // signalCount

         // signals: name, argc, parameters, tag, flags
               1,    1,   24,    2, 0x06 /* Public */,

         // slots: name, argc, parameters, tag, flags
               4,    1,   27,    2, 0x0a /* Public */,

         // signals: parameters
            QMetaType::Void, QMetaType::Int,    3,

         // slots: parameters
            QMetaType::Void, QMetaType::Int,    5,

               0        // eod
        };

        struct qt_meta_stringdata_Counter_t {
            QByteArrayData data[6];
            char stringdata0[46];
        };
        #define QT_MOC_LITERAL(idx, ofs, len) \
            Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
            qptrdiff(offsetof(qt_meta_stringdata_Counter_t, stringdata0) + ofs \
                - idx * sizeof(QByteArrayData)) \
            )
        static const qt_meta_stringdata_Counter_t qt_meta_stringdata_Counter = {
            {
        QT_MOC_LITERAL(0, 0, 7), // "Counter"
        QT_MOC_LITERAL(1, 8, 12), // "valueChanged"
        QT_MOC_LITERAL(2, 21, 0), // ""
        QT_MOC_LITERAL(3, 22, 8), // "newValue"
        QT_MOC_LITERAL(4, 31, 8), // "setValue"
        QT_MOC_LITERAL(5, 40, 5) // "value"

            },
            "Counter\0valueChanged\0\0newValue\0setValue\0"
            "value"
        };
        #undef QT_MOC_LITERAL

    For reference see <https://woboq.com/blog/how-qt-signals-slots-work.html>.
    """
    INT = getDataTypes('int')[0]
    HEADER_DATATYPE, _ = get()

    HEADER_FIELD_CLASSNAME_INDEX = 1
    HEADER_FIELD_METHODS_COUNT_INDEX = 4
    HEADER_FIELD_METHODS_INDEX_INDEX = 5
    HEADER_FIELD_PROPS_COUNT_INDEX = 6
    HEADER_FIELD_PROPS_INDEX_INDEX = 7
    HEADER_FIELD_ENUMS_COUNT_INDEX = 8
    HEADER_FIELD_ENUMS_INDEX_INDEX = 9


    def __init__(self, address):
        self.address = address

        pointer_size = currentProgram.getCompilerSpec().getDataOrganization().getPointerSize()

        self.staticMetaObject = common.get_value(address, PointerDataType.dataType)
        self.stringdata       = common.get_value(address.add(pointer_size), PointerDataType.dataType)
        self.data             = common.get_value(address.add(2*pointer_size), PointerDataType.dataType)
        self.static_metacall  = common.get_value(address.add(3*pointer_size), PointerDataType.dataType)

        self.methods = {}  # this will contain the idx: method name

        # sanity check
        is_original_staticMetaObject = self.staticMetaObject == staticMetaObject.getAddress()

        if not is_original_staticMetaObject:
            symbol_at = getSymbolAt(self.staticMetaObject)

            if symbol_at is None:
                #raise ValueError("Nothing is defined at {}: you should set the cursor at the start of a MetaObject vtable".format(self.staticMetaObject))
                logger.warning("no symbol defined, proceed wit caution")
            elif  "staticMetaObject" not in symbol_at.getName():
                logger.warning("you must have a cursor on a memory that references staticMetaObject instead of %s" % symbol_at)
            else:
                logger.info("this class derives from '%s'" % (symbol_at.getParentNamespace()))

        # obtain the info from the memory
        self.__build()

        # set the qt_metacast method as best as we can
        if self.static_metacall.getOffset() != 0:
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
        ns = currentProgram.getSymbolTable().getNamespace(self.class_name, None)

        if klass is None and ns is None:
            logger.info("creating class '{}'".format(self.class_name))
            klass = currentProgram.symbolTable.createClass(None, self.class_name, SourceType.USER_DEFINED)
        elif klass is None and ns is not None:
            logger.info("converting namespace '{}' to class".format(self.class_name))
            klass = currentProgram.getSymbolTable().convertNamespaceToClass(ns)
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

        datatype_call = get_Call_enum()

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
            self.header.getComponent(self.HEADER_FIELD_CLASSNAME_INDEX).value.getValue()).data.value

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
            print idx, hex(idx), attr_name, "(",

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
                print hex(param), hex(param_name_idx),
                param_name = self._get_qstring_at(param_name_idx & 0x7fffffff).getString()
                print param_name, ",",

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

        # if we don't have anything to show won't show the table
        if tableDialog.getRowCount() > 0:
            tableDialog.show()

    def find_signals(self):
        """The idea here is that QMetaObject::activate() with our MetaObject vtable
        will identify all the signals of this object."""
        activate = common.get_function_by_name('activate', namespace='QMetaObject')

        # where activate() is called
        xrefs_activate = common.get_functions_via_xref(activate.entryPoint)

        logger.debug("xrefs to activate(): {}".format(xrefs_activate))

        # where out MetaObject vtable is referenced
        xrefs_metavtable_func = [func for call_addr, func in common.get_functions_via_xref(self.address)]
        logger.info("xrefs to metatable: {}".format(xrefs_metavtable_func))

        # where the xrefs are not inside a function (we suppose are to be defined)
        undefined = filter(lambda _: _ is None, xrefs_metavtable_func)

        logger.info("TODO: table for {}".format(undefined))

        import collections

        # we look only for functions where there is only one xref
        xrefs_activate_counted = collections.Counter([_[1] for _ in xrefs_activate])
        xrefs_activate = [(call_addr, func) for call_addr, func in xrefs_activate if xrefs_activate_counted[func] == 1]

        logger.debug(xrefs_activate_counted)

        # this will be useful later
        klass = self.get_ghidra_class()

        # show the undefined
        #if undefined:
        #    self._show_undefined_functions(undefined)

        # take the xrefs (functions) that are common
        xrefs = [(call_addr, func) for call_addr, func in xrefs_activate if func in xrefs_metavtable_func]

        logger.debug(xrefs)

        for call_addr, func in xrefs:
            if func is None:
                # jump the not defined functions
                continue

            """
            TODO: Now the logic to follow would be
            
            1. it's the unique call inside that function
            2. the first parameter is a function parameter
            """
            # give me the arguments please

            caller = common.getCallerInfo(activate, func, call_addr)
            logger.debug(func)
            logger.info(caller)
            # we obtain the signal name from the index (third argument)
            signal_index = caller[3]
            signal_name = self.methods[signal_index]

            logger.info("found signal: '{}'".format(signal_name))

            func.setParentNamespace(klass)
            func.setCallingConvention('__thiscall')

            if not func.getName().startswith("FUN_"):
                logger.warning("not changing function name since it seems user generated")
                continue

            logger.info("renaming {} -> {}".format(func.getName(), signal_name))

            func.setName(signal_name, SourceType.USER_DEFINED)

    def find_meta_object(self):
        """Try to find a cross reference between this class MetaObject vtable
        and a call to QObjectData::dynamicMetaObject()."""

        xrefs_metavtable = common.get_functions_via_xref(self.address)
        dynamicMetaObject = common.get_function_by_name('dynamicMetaObject')

        xrefs_dynamic = common.get_functions_via_xref(dynamicMetaObject.entryPoint)
        xrefs_dynamic_w_func = [_[1] for _ in xrefs_dynamic if _[1] is not None]

        return [_ for _ in xrefs_metavtable if _[1] in xrefs_dynamic_w_func]


obj = QMetaObject(currentAddress)

print obj
