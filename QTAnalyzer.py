# Try to find stuff related to QT
#@author 
#@category QT
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SourceType


dataType = getDataTypes("QArrayData")

if len(dataType) < 1:
	raise ValueError("You must define the QArrayData type")

dataType = dataType[0]

# create data at the cursor position
data = createData(currentAddress, dataType)

# sanity check
if data.getComponent(0).value.getValue() != -1:
	raise ValueError("We are expecting -1 for the 'ref' field")

# create reference
rm = currentProgram.getReferenceManager()
to_address = currentAddress.add(data.getComponent(3).value.getValue())

rm.addOffsetMemReference(currentAddress, to_address, data.getComponent(3).value.getValue(), RefType.DATA, SourceType.USER_DEFINED, 0)

to_data = getDataAt(to_address)

# create a label mimicking the data
# label =
createLabel(currentAddress, 'QARRAYDATA_%s' % to_data.value, True)

# move the cursor at the adjacent location
goTo(currentAddress.add(dataType.getLength()))

