import logging
import struct


class VMIStruct:

    STANDARD_TYPES = {
        'unsigned char': '=B',
        'unsigned long': '=L',
        'unsigned long long': '=Q',
        'long': '=l'
    }

    def __init__(self, vmi, structs_profile, struct_name, addr):
        self.vmi = vmi
        self.structs_profile = structs_profile
        self.addr = addr
        self.name = struct_name
        try:
            struct = self.structs_profile[self.name]
        except KeyError:
            raise AttributeError
        else:
            self.size, self.profile = struct

    def read_field(self, addr, format=None, pointer=False):
        if pointer:
            return self.vmi.read_addr_va(addr, 0)
        else:
            if not format:
                logging.error('Specify either format or pointer')
            count = struct.calcsize(format)
            buffer, bytes_read = self.vmi.read_va(addr, 0, count)
            if bytes_read != count:
                raise RuntimeError('Failed to read field')
            return int.from_bytes(buffer, byteorder='little')

    def __getattr__(self, item):
        try:
            offset, field_info = self.profile[item]
        except KeyError:
            raise AttributeError('Unknown field %s in %s', item, self.name)
        else:
            # ignore target
            field_type, target_info = field_info
            format = None
            try:
                format = self.STANDARD_TYPES[field_type]
                return self.read_field(self.addr + offset, format)
            except KeyError:
                # assume complex data type, read pointer
                pointer = self.read_field(self.addr + offset, pointer=True)

                # Pointer ?
                if field_type == 'Pointer':
                    if target_info['target'] == 'Void':
                        return pointer
                    else:
                        return VMIStruct(self.vmi, self.structs_profile, target_info['target'], pointer)
                elif not target_info:
                    # inline struct
                    return VMIStruct(self.vmi, self.structs_profile, field_type, self.addr + offset)
                else:
                    # array, not implemented
                    raise RuntimeError('unimplemented struct %s', item)
