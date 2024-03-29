import logging

from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import SymbolUtilities
"""
    self.data = createUnicodeString(to_address)
	at ghidra.program.database.code.CodeManager.checkValidAddressRange(CodeManager.java:1970)
	at ghidra.program.database.code.CodeManager.createCodeUnit(CodeManager.java:2055)
	at ghidra.program.database.ListingDB.createData(ListingDB.java:422)
	at ghidra.program.flatapi.FlatProgramAPI.createData(FlatProgramAPI.java:1658)
	at ghidra.program.flatapi.FlatProgramAPI.createUnicodeString(FlatProgramAPI.java:1790)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.base/java.lang.reflect.Method.invoke(Method.java:566)
ghidra.program.model.util.CodeUnitInsertionException: ghidra.program.model.util.CodeUnitInsertionException: Conflicting data exists at address 00403f20 to 00403f23
"""
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.data import StructureDataType, IntegerDataType, DataTypeConflictHandler

# this below allows to have the global objects as in the scripts themself
# see <https://github.com/NationalSecurityAgency/ghidra/issues/1919>
from __main__ import *
import common

# FIXME: it's tricky to define "complex" data types
#        via C parsing since it seems that ghidra
#        doesn't parse correctly if some other archives
#        must be parsed before
QARRAY_DECLARATION = """
struct QArrayData {
	int ref;
	int size;
	unsigned int alloc; /* this is a bitfield */
	ptrdiff_t offset;
};
"""


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


def create():
	"""Create programmatically the QArrayData data type extracting
	the information from the CompilerSpec class."""
	logger.warning("creating QArrayData")

	name = "QArrayData"

	qarraydata = StructureDataType(name, 0)
	qarraydata.add(
		IntegerDataType.dataType,
		currentProgram.getCompilerSpec().getDataOrganization().getIntegerSize(),
		"ref",
		"")
	qarraydata.add(IntegerDataType.dataType,
		currentProgram.getCompilerSpec().getDataOrganization().getIntegerSize(),
		"size",
		"")
	qarraydata.add(IntegerDataType.dataType,
		currentProgram.getCompilerSpec().getDataOrganization().getIntegerSize(),
		"alloc",
		"")

	# we need to pack the structure
	qarraydata.setToDefaultPacking()

	# for the offset we need to get the datatype that have the same size of a pointer
	# but is an integer; see <https://doc.qt.io/qt-6/qtglobal.html#qptrdiff-typedef>
	pointer_size = currentProgram.getCompilerSpec().getDataOrganization().getPointerSize()
	ptrdiffDataType = IntegerDataType.getSignedDataType(
		pointer_size,
		currentProgram.getDataTypeManager(),
	)
	qarraydata.add(
		ptrdiffDataType,
		pointer_size,
		"offset",
		"")  # this should be ptrdiff_t

	currentProgram.getDataTypeManager().addDataType(qarraydata, DataTypeConflictHandler.REPLACE_HANDLER)

	# you need to requery; since it has no category indicated you should obtain the first one
	return getDataTypes(name)[0]


def get():
	"""Return the QArrayData data type or create programmatically it."""
	data_types = getDataTypes('QArrayData')

	# usually under "/Demangler" it exists an empty structure defined
	if len(data_types) == 0 or data_types[0].isNotYetDefined() or data_types[0].getLength() != 16:
		return create(), True

	return data_types[0], False


def slugify(label):
	"""Replace invalid characters with underscores"""
	return SymbolUtilities.replaceInvalidChars(label, True)


class QString:
	INDEX_QARRAYDATA_OFFSET = 3
	INDEX_QARRAYDATA_LENGTH = 1

	dataType, _ = get()

	def __init__(self, address):
		self.address = address

		# sanity check (probably some more TODO)
		if getInt(address) != -1:
			raise ValueError("We are expecting -1 for the 'ref' field")

		# create data at the wanted position
		self._d = createData(address, self.dataType)

		# create reference
		rm = currentProgram.getReferenceManager()

		to_address = address.add(self.offset)

		rm.addOffsetMemReference(
			address,
			to_address,
			self.offset,
			RefType.DATA,
			SourceType.USER_DEFINED,
			0,
		)

		self.data = getDataAt(to_address)

		# we try to define a unicode string but maybe
		# some others data was defined before so we simply
		# get the string and whatever
		if self.data is None:
			try:
				self.data = createUnicodeString(to_address)
				str_ = self.data.value
			except CodeUnitInsertionException as e:
				logger.warning("--- code conflict below ---")
				logger.exception(e)
				logger.warning("---------------------------")
				# we haven't any data defined, use unicode
				self.data = common.get_bytes_from_binary(to_address, self.size * 2)
				str_ = self.data.decode('utf-16le')
		else:
			str_ = self.data.value

		createLabel(address, 'QARRAYDATA_%s' % slugify(str_), True)

	@classmethod
	def getHeaderSize(cls):
		return cls.dataType.getLength()

	@property
	def offset(self):
		return self._d.getComponent(self.INDEX_QARRAYDATA_OFFSET).value.getValue()

	@property
	def size(self):
		"""This is the value as is, if you need the length of the unicode encode
		data you need to multiply this by 2."""
		return self._d.getComponent(self.INDEX_QARRAYDATA_LENGTH).value.getValue()

	@property
	def end(self):
		"""Return the address where the data pointed by this ends"""
		return self.address.add(self.offset + self.size * 2)

	@property
	def end_aligned(self):
		"""Return the address where the data pointed by this end but aligned"""
		return self.address.add((self.offset + (self.size + 1) * 2 + 3) & 0xfffffc)  # FIXME: generate mask

	def getString(self):
		return self.data if type(self.data) == str else self.data.value
