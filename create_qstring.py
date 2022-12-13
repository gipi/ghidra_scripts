# Create QString at the cursor
#@author Gianluca Pacchiella
#@category QT
#@keybinding SHIFT-S
#@menupath
#@toolbar
import QString
def main(address):

	string = QString(address)
	# check if just after the QArrayData there is another one
	address_next = address.add(string.dataType.getLength())
	value = getInt(address_next)

	if value != -1:
		# or move the cursor at the end of the string
		address_next = string.end_aligned

	goTo(address_next)


main(currentAddress)