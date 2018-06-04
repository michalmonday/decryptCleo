data = "93 BE F9 FF" # offset (e.g. addr label jump) copied from cleo, found using HxD program
 
def C(data): 
   data = int(int("FFFFFFFF", 16) - int("".join(reversed(data.split())), 16) + 1)
   print str(hex(data)) + " ("+str(data)+")"
 
C(data) # will print int/hex value so we can navigate in HxD and see exactly what is executed next

'''
def TB(data, xor_value): # translate bytes
    #xor_value = int(raw_input("XOR value =\n> "))
    new_data = [hex(int(b,16) ^ xor_value) for b in data.split(" ")]
    new_data = [c[-2:] if len(c) > 3 else "0" + c[-1:] for c in new_data]
    print ""
    print " ".join(new_data)

def Sub(data):
    data_copy = data.split(" ")
    new_data = []
    for i, c in enumerate(data.split(" ")):
        if i%2 == 0 and i < len(data_copy)-2:
            new_data.append(data_copy[i+1])
            new_data.append(data_copy[i])
    print " ".join(new_data)
    
def TBF(f_name, xor_value): # translate bytes
    with open(f_name, "r") as f:
        data = f.read()
    #xor_value = int(raw_input("XOR value =\n> "))
    new_data = [hex(int(b,16) ^ xor_value) for b in data.split(" ")]
    new_data = [c[-2:] if len(c) > 3 else "0" + c[-1:] for c in new_data]
    print ""
    print " ".join(new_data)

def TF(data, f_name): # TO FILE
    with open(f_name + ".cs", "wb+") as f:
        f.write("".join([chr(int(b, 16)) for b in data.split(" ")]))
'''









'''
1. Copy hex representation of memory from Cheat Engine or HxD program into txt file.
2. Use the code below to transform hex representation of memory to the actual memory.
3. Open the newly created file with Sanny Builder

For sample you have "mem.txt" with "61 62" text inside it.
After transforming it using this code you'll have "ab" inside it.
That's because 0x61 is ascii value of "a" character and 0x62 for "b".
'''

def Transform(f_name):
   with open(f_name+".txt", "rb") as f:
      data = f.read()
      
   new_data=""
   for h in data.split(" "):
       new_data += chr(int(h,16))


   with open(f_name+".cs", "wb") as f:
       f.write(new_data)


      




   


