def authenticateUser():
    username = input("Please enter a valid username\n")
    password = input("Please enter a valid password\n")
 
    if username.toLower() == 'eve' and password == 'reilly':
       return 1
    
    else:
       print("Please Enter Valid username and password\n")
       authenticateUser()sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

sock.bind(("0.0.0.0", 0)) # Bind to all interfaces

sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

try:

sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

except AttributeError:

pass # For non-Windows systems

captured_data = []

print(f"Capturing {packet_count} packets...")

for _ in range(packet_count):

packet = sock.recvfrom(65565)

packet_data = packet[0]

source_ip = '.'.join(map(str, packet_data[12:16]))

destination_ip = '.'.join(map(str, packet_data[16:20]))

captured_data.append([source_ip, destination_ip])


with open(output_file, mode='w', newline='') as file:

writer = csv.writer(file)

writer.writerow(['Source IP', 'Destination IP'])

writer.writerows(captured_data)


print(f"\nPacket capture completed. Data saved to {output_file}.")

try:

sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

except AttributeError:

pass # For non-Windows systems

sock.close()

except PermissionError:

print("Permission denied: Please run the script as Administrator.")

