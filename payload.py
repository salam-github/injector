import lief
import sys

def inject_payload(target, payload_path):
    # Load the target ELF file
    elf = lief.parse(target)
    
    # Read the payload content
    with open(payload_path, 'rb') as payload_file:
        payload_data = payload_file.read()
    
    # Create a new section for the payload
    new_section = lief.ELF.Section(".injected")
    new_section.content = list(payload_data)  # LIEF expects the content as a list of integers
    new_section.type = lief.ELF.SECTION_TYPES.PROGBITS
    new_section.add(lief.ELF.SECTION_FLAGS.EXECINSTR | lief.ELF.SECTION_FLAGS.ALLOC)
    
    # Add the new section to the ELF file
    elf.add(new_section)
    
    # Adjust the ELF entry point if necessary
    # elf.header.entrypoint = new_section.virtual_address

    # Build the modified ELF
    builder = lief.ELF.Builder(elf)
    builder.build()
    builder.save('modified_' + target)  # Saves the modified ELF file
    
    print(f'Injected {payload_path} into {target} with modifications.')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python injector.py <target> <payload>')
        sys.exit(1)
        
    target = sys.argv[1]
    payload_path = sys.argv[2]
    
    inject_payload(target, payload_path)
