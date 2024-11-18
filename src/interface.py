from scapy.arch.windows import get_windows_if_list

# Get the list of interfaces and their corresponding details
interfaces = get_windows_if_list()

# Print out each interface with its corresponding name, description, and UUID
for iface in interfaces:
    print(f"Name: {iface['name']}, Description: {iface['description']}, UUID: {iface['guid']}")
