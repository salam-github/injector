import sys

def inject_binary(target, payload):
    # Read the payload
    with open(payload, 'rb') as payload_file:
        payload_content = payload_file.read()
        
    # Read the target and append the payload
    with open(target, 'ab') as target_file:
        target_file.write(payload_content)
        
    print(f'Injected {payload} into {target}')
    
    
if __name__ == '__main__':
    if len (sys.argv) != 3:
        print('Usage: python injector.py <target> <payload>')
        sys.exit(1)
        
    target = sys.argv[1]
    payload = sys.argv[2]
    
    inject_binary(target, payload)