# Extract QML resource files
#@author Gianluca Pacchiella
#@category QT
#@keybinding 
#@menupath 
#@toolbar
"""
Resources on QT are registered using

  bool qRegisterResourceData(int version, const unsigned char *tree,
                                         const unsigned char *name, const unsigned char *data)

This script looks for calls to this function and after extracting the arguments tries to
rebuild the resource files.

"tree" is the data structure containing the description of the filesystem tree, how many child
a node has (like a filesystem does); "name" and "data" contain the actual identifier for a given node
and the data associated (but take in mind that the data is only for the leaf node, i.e. the files).

To understand the layout of the data look at the method

  RCCResourceLibrary::output()

and the methods it internally calls

  writeDataBlobs()
  writeDataNames()
  writeDataStructure()
"""
import logging
import os
import struct
import zlib
from collections import deque

from ghidra.program.model.data import (
    UnsignedIntegerDataType,
    ShortDataType,
    StructureDataType,
    UnsignedLongLongDataType,
    EndianSettingsDefinition,
    DataTypeConflictHandler,
    CategoryPath,
)

import common


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel("INFO")

# first of all we get the data type we want
# remember all the fields are big endian
# probably should be created programmatically
RESOURCE_STRUCT_DECLARATION = """
struct resource_struct_t {
    unsigned int name_offset;
    short flags;
    unsigned int mix;
    unsigned int offset;
    unsigned long long lastmod;
};
"""


def create():
    """Create programmatically the struct we need.

    In theory this data type doesn't contain anything exotic BUT since
    it's unaligned (because of the short) the CParser add unwanted padding."""
    logger.warning("creating resource_struct_t")
    resource = StructureDataType("resource_struct_t", 0)

    resource.setCategoryPath(CategoryPath("/script"))

    resource.add(UnsignedIntegerDataType.dataType, 0, "name_offset", "")
    resource.add(ShortDataType.dataType, 0, "flags", "")
    resource.add(UnsignedIntegerDataType.dataType, 0, "mix", "")
    resource.add(UnsignedIntegerDataType.dataType, 0, "offset", "")
    resource.add(UnsignedLongLongDataType.dataType, 0, "lastmod", "")

    # you have to save it
    dtm = currentProgram.getDataTypeManager()
    dtm.addDataType(resource, DataTypeConflictHandler.REPLACE_HANDLER)

    resource = dtm.getDataType("/script/resource_struct_t")

    # then fix the endianess
    # https://reverseengineering.stackexchange.com/questions/23330/ghidra-python-create-struct-with-big-endian-field
    for component in resource.getComponents():
        component_settings = component.getDefaultSettings()
        component_settings.setLong('endian', EndianSettingsDefinition.BIG)

    # and then requery again
    return dtm.getDataType("/script/resource_struct_t")


def get():
    dtm = currentProgram.getDataTypeManager()

    resource_struct_t = dtm.getDataType("/script/resource_struct_t")

    if not resource_struct_t:
        return create(), True

    return resource_struct_t, False


class RCCFileInfoNode:
    # value taken from rcc.cpp, class RCCFileInfo
    COMPRESSED = 1
    DIRECTORY = 2
    COMPRESSED_ZSTD = 4

    def __init__(self, name, is_dir, parent=None, **kwargs):
        self.name = name
        self.is_dir = is_dir
        self.parent = parent

        self.is_compressed = kwargs['is_compressed']

        if is_dir:
            self.child_offset = kwargs['child_offset']
            self.child_size = kwargs['child_size']
        else:
            self.data = kwargs['data']

    def __str__(self):
        return self.name


class QResourceRoot:
    """The instance holds the base addresses for tree, names and data from which
    obtain the node information."""
    def __init__(self, addr_root, addr_names, addr_data):
        self.root = addr_root
        self.names = addr_names
        self.data = addr_data

        self.resource_struct, _ = get()

    @staticmethod
    def __build(node, parent=None):
        data = {
            'name_offset': node.getComponent(0).value.value,
            'flags': node.getComponent(1).value.value,
            'lastmod': node.getComponent(4),
        }

        data['is_dir'] = bool(data['flags'] & RCCFileInfoNode.DIRECTORY)
        data['is_compressed'] = bool(data['flags'] & RCCFileInfoNode.COMPRESSED)

        if data['is_dir']:
            data['child_size'] = node.getComponent(2).value.value
            data['child_offset'] = node.getComponent(3).value.value
        else:
            data['data_offset'] = node.getComponent(3).value.value

        # print data

        return data

    def __get_name(self, name_offset):
        size = common.get_bytes_from_binary(self.names.add(name_offset), 2)
        size = struct.unpack(">h", size)[0]
        # we are asking for unicode so we double the data
        return common.get_bytes_from_binary(self.names.add(name_offset + 2 + 4), size * 2).decode('utf16')

    def __get_data(self, data_offset, is_compressed):
        """The data part has the length of the data is exposed as a 4 byte Big ending value."""
        size = common.get_bytes_from_binary(self.data.add(data_offset), 4)
        size = struct.unpack(">I", size)[0]

        # print "getting #{} bytes of data from offset {}".format(size, data_offset)

        # we have two possibilities:
        #  1. the data is as is, so we jump the size and use that size as is
        #  2. the data is compressed, qCompress() add another 4bytes big-endian
        #     at the start of the compressed blob with the original file size
        #     and then the compressed blob itself (so we have to reduce by 4 the
        #     original size).
        offset = 8 if is_compressed else 4
        size = size - 4 if is_compressed else size
        data = common.get_bytes_from_binary(self.data.add(data_offset + offset), size)

        # if it's compressed you can decompress it via zlib
        return  zlib.decompress(data) if is_compressed else data

    def __create_data(self, address):
        logger.info("Creating data @ {}".format(address))
        return createData(address, self.resource_struct)

    def build_from_address(self, address):
        _data = getDataAt(address)

        if _data is None:
            _data = self.__create_data(address)
        elif _data.getDataType() != self.resource_struct:
            logger.warning("cleaning {} at {}".format(_data.getDataType(), address))
            removeData(_data)
            _data = self.__create_data(address)

        data = self.__class__.__build(_data)

        name_offset = data.pop('name_offset')

        if not data['is_dir']:
            data['data'] = self.__get_data(data['data_offset'], data['is_compressed'])

        return RCCFileInfoNode(
            self.__get_name(name_offset),
            **data
        )

    def address_for_offset(self, offset):
        return self.root.add(self.resource_struct.length*offset)

    def node_at(self, offset):
        return self.build_from_address(self.address_for_offset(offset))

    def get_child_of(self, node):
        offset_start = node.child_offset
        count = node.child_size

        childs = []

        for offset in range(offset_start, offset_start + count):
            child = self.node_at(offset)
            child.parent = node
            childs.append(child)

        return childs


def dump_file(node, path_root):
    # save the original node that is the lead of the tree
    file = node

    # if it's a file it has a parent directory (probably?)
    if node.parent is not None:
        components = [node]
        while node.parent is not None:
            node = node.parent
            components.append(node)

        # build the complete path
        components.reverse()
        path = "/".join([str(_) for _ in components])

        logger.info("saving {} ({}compressed)".format(path, "" if file.is_compressed else "no "))

        # append to the path chosen for the dump
        path = os.path.join(path_root, path)

        # check if the directory that will contain the file exists
        # and create in case doesn't
        dir_containing = os.path.dirname(path)
        if not os.path.exists(dir_containing):
            os.makedirs(dir_containing)

        # save the data
        with open(path, "wb") as output:
            output.write(file.data)


def dump_root(path_dump, struct_addr, name_addr, data_addr):
    ROOT = QResourceRoot(struct_addr, name_addr, data_addr)
    nodes = deque()

    root = ROOT.node_at(0)

    nodes.append(root)

    while len(nodes) > 0:
        node = nodes.pop()
        # print "found node {}".format(node)

        if not node.is_dir:
            dump_file(node, path_dump.path)
            continue

        nodes.extend(ROOT.get_child_of(node))


def main():
    path_dump = askDirectory("Choose a directory where we'll dump the source tree", "Ok")

    qRegisterResourceData = common.get_function_by_name('qRegisterResourceData')

    for call_address, function in  common.get_functions_via_xref(qRegisterResourceData.entryPoint):
        if not function:
            continue

        try:
            info = common.getCallerInfo(qRegisterResourceData, function, call_address)
        except:
            raise ValueError("Probably the arguments at {} are not 'clean' enough".format(call_address))

        dump_root(path_dump, *map(toAddr, info[2:]))


main()