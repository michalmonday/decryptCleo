

# GetData and SaveData functions are here just to save some space
def GetData():
    with open(f_name+".cs", "rb") as f:
        data = f.read()
    return data

def SaveData(new_data, ending):
    if ending:
        whole_name = f_name + "_" + ending + ".cs"
    else:
        whole_name = f_name + "_new.cs"
    with open(whole_name,"wb+") as f:
        f.write(new_data)
    return


# There's a tricky method which prevents Sanny Builder from
# displaying label offsets and tells it to show "jump NAN.0"
# instead of "jump @SomeName_357". This function searches through
# the cleo memory, finds jump/jump_if_false opcodes and sets the "06"
# which indicates float (?) into "01" which indicates integer (?)
def FixLabelDatatype_Float_To_Int(data):
    vulnerable_opcodes = [
        "0002", # jump
        "004D", # jump_if_false
        "0050", # gosub
        "0006", # 0@ = 5555
        "000E", # 000E: 0@ -= 1
        "0AB1",
        ]
    new_data = ""
    for i, char in enumerate(data[:-1]):
        found_opcode = False
        char_to_add = data[i]
        #print " ".join(["{:02X}".format(ord(c)) for c in data[i-6:i+5]])
        for opcode in vulnerable_opcodes:
            if ord(data[i-2]) == int(opcode[2:],16) and ord(data[i-1]) == int(opcode[:2],16) and found_opcode == False and opcode != "0006":
                if (data[i] == "\x06" and data[i+4] == "\xFF"):
                    char_to_add = chr(1)
                    found_opcode = True
                    print " ".join(["Found " + opcode + " at offset " + str(i) + " :\n"] + ["{:02X}".format(ord(c)) for c in data[i-2:i+1]])

            #00 0E 00 03 1F 00 06 2D FF FF FF   
            if opcode == "000E" and i > 6 and i < len(data)-9:
                if data[i] == "\x06" and data[i+4] == "\xFF" and ord(data[i-5]) == int(opcode[2:],16): #and ord(data[i-6]) == int(opcode[:2],16)
                    char_to_add = chr(1)
                    found_opcode = True
                    print " ".join(["Found " + opcode + " at offset " + str(i) + " :\n"] + ["{:02X}".format(ord(c)) for c in data[i-6:i+5]])
                

            if i > 4:
                if opcode == "0006" and ord(data[i-5]) == int(opcode[2:],16) and ord(data[i-4]) == int(opcode[:2],16) and found_opcode == False: # 0006 
                    if data[i] == "\x06":
                        char_to_add = chr(1)
                        found_opcode = True
                        print " ".join(["Found " + opcode + " at offset " + str(i) + " :\n"] + ["{:02X}".format(ord(c)) for c in data[i-5:i+1]])
                

        new_data += char_to_add
    return new_data




def FixLabels_SaveFile():
    data = GetData()
    data = FixLabelDatatype_Float_To_Int(data)
    SaveData(data, "fixed")
'''
f_name = "afk"
FixLabels_SaveFile()
'''




# SimpleNegative255
'''
f_name = "admin_mode"
starting_offset = 39
length = 18169
'''

def SimpleNegative255():
    data = GetData()
    new_data = ""
    
    for c in data[starting_offset:length+starting_offset]:
        new_data += chr(255 - ord(c))
    '''
    for c in data[int("7C",16):]:
        new_data += chr(ord(c) ^ 38)
    '''
    SaveData(new_data, "new")
    return




#FYP_XOR_CrossSided settings
'''
f_name = "objectFinder"
starting_offset = 15
length = 44495
initial_limiter = 16 # val / initial limiter * initial limiter
initial_limiter_starting_offset = 44511
'''

'''
f_name = "Shanker_Free_P1"
starting_offset = 15
length = 63741
initial_limiter = 16 # val / initial limiter * initial limiter
initial_limiter_starting_offset = 63757
'''

'''
f_name = "2nd_thread"
starting_offset = 15
length = 26239
initial_limiter = 16 # val / initial limiter * initial limiter
initial_limiter_starting_offset = 26255
'''


def FYP_XOR_CrossSided(): # objectFinder "by K1ddu"
    data = GetData()
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ ord(data[i - (i/16*16) + initial_limiter_starting_offset]))
    SaveData(new_data, "new_orig")
    return



def FYP_XOR_CrossSided(data, starting_offset, length, initial_limiter, initial_limiter_starting_offset):
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ ord(data[i - (i/16*16) + initial_limiter_starting_offset]))
    return new_data    


#FuncProtector_XOR settings
'''
f_name = "CruiseControl"
starting_offset = 0
length = 23899
xor_value = 70
'''

def FuncProtector_XOR():
    '''
        call @Noname_1549 1 -104 
        1@ -= -1429 
        0A9F: 2@ = current_thread_pointer 
        2@ += 16 
        0A8D: 3@ = read_memory 2@ size 4 virtual_protect 1 
        0062: 3@ -= 0@ // (int) 
        4@ = 0 
        0A8E: 5@ = 3@ + 4@ // int 
        0A8D: 6@ = read_memory 5@ size 1 virtual_protect 1 
        7@ = 51 
        0B12: 6@ = 6@ XOR 7@ 
        0A8C: write_memory 5@ size 1 value 6@ virtual_protect 1 
        4@ += 1 
        001D:   4@ > 1@ // (int) 
        jf @Noname_1598
    '''
    data = GetData()
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)

    SaveData(new_data, "new")
    return





#YcE "chat" riddle
'''
f_name = "copy_chat"
starting_offset = 39
length = 19143

starting_offset_2 = 39
length_2 = 18950

starting_offset_3 = 39
length_3 = 18757

starting_offset_4 = 7
length_4 = 18563

starting_offset_5 = 39
length_5 = 18319
'''
 
def YcE_Riddle():
    data = GetData()

    new_data = ""
    for c in data[starting_offset:length+starting_offset]:
        new_data += chr(255 - ord(c))
    
    SaveData(new_data, "1")    

    new_data_2 = ""
    for c in new_data[starting_offset_2:length_2+starting_offset_2]:
        new_data_2 += chr(255 - ord(c))

    SaveData(new_data_2, "2")
    
    new_data_3 = ""
    for c in new_data_2[starting_offset_3:length_3+starting_offset_3]:
        new_data_3 += chr(255 - ord(c))

    SaveData(new_data_3, "3")
    
    new_data_4 = ""
    data_copy = new_data_3[starting_offset_4:length_4+starting_offset_4]
    for i, c in enumerate(data_copy):
        if i%2 == 0 and i < length_4-1:
            new_data_4 += data_copy[i+1] + data_copy[i]

    SaveData(new_data_4, "4")

    new_data_5 = ""
    for i, c in enumerate(new_data_4[starting_offset_5:length_5+starting_offset_5]):
        if i%2 == 1:
            new_data_5 += chr(255 - ord(c))
        else:
            new_data_5 += c

    SaveData(new_data_5, "5")        






#DecryptParazitas
'''
f_name = "Decrypt"
length = 653
starting_offset = 13
address_xor = 666
xor_switch_step = 16

length_2 = 369
starting_offset_2 = 13

length_3 = 86
starting_offset_3 = 13
xor_value = 74
'''

def DecryptParazitas():
    '''
    data = GetData()
    
    SaveData(data, "fixed")
    '''
    global address_xor
    data = GetData()
    #data = FixLabelDatatype_Float_To_Int(data)
    new_data = ""
    data_copy = data
    for i, c in enumerate(data[starting_offset: length + starting_offset]):
        if i % xor_switch_step == 0:
            offset_xor = 0     
        new_data += chr(ord(c) ^ ord(data_copy[address_xor+offset_xor]))
        offset_xor += 1

    #new_data = FixLabelDatatype_Float_To_Int(new_data)
    SaveData(new_data, "new")

    new_data_2 = ""
    for c in new_data[starting_offset_2:length_2+starting_offset_2]:
        new_data_2 += chr(255 - ord(c))
    #new_data_2 = FixLabelDatatype_Float_To_Int(new_data_2)

    new_data_3 = ""
    for c in new_data_2[starting_offset_3: length_3+starting_offset_3]:
        new_data_3 += chr(ord(c) ^ xor_value)
    new_data_3 = FixLabelDatatype_Float_To_Int(new_data_3)
    SaveData(new_data_3, "new")


#Tbot label fix
'''
f_name = "Tbot"
'''

def TbotLabelFix():
    data = GetData()
    data = FixLabelDatatype_Float_To_Int(data)
    SaveData(data, "new")


#Double_255_with_paired_substitution settings
'''
f_name = "chat"
starting_offset = 39
length = 18950
second_starting_offset = 7
second_length = 18563
'''

# MultipleNegative255
'''
f_name = "admin_mode"
starting_offset = 39
length = 18169

starting_offset_2 = 39
length_2 = 18555
'''

def MultipleNegative255():
    data = GetData()
    new_data_2 = ""
    data_copy = data[39:18748+39]
    for i, c in enumerate(data_copy):
        if i%2 == 0 and i < 18748-1:
            new_data_2 += data_copy[i+1] + data_copy[i]

    SaveData(new_data_2, "sub_norm")
    
    new_data = ""
    for c in new_data_2:
        new_data += chr(255 - ord(c))

    SaveData(new_data, "sub_norm_255")
    
    #for i, c in enumerate(data[starting_offset:length+starting_offset]):
    #    new_data[i] = chr(255 - ord(c))
    #SaveData("".join(new_data), "new")

    #for i, c in enumerate(data[starting_offset_2:length_2+starting_offset_2]):
    #    new_data[i] = chr(255 - ord(c))
    #SaveData("".join(new_data), "new")

        
    #SaveData(new_data_2, "new")
    return




# Sarg
'''
f_name = "Sarg"
length = 15387
starting_offset = 13
address_xor = 15400
xor_switch_step = 16


length_2 = 15103
starting_offset_2 = 13


length_3 = 14820 
starting_offset_3 = 13
xor_value = 205
'''

def Sarg():
    global address_xor
    data = GetData()
    #data = FixLabelDatatype_Float_To_Int(data)
    new_data = ""
    data_copy = data
    for i, c in enumerate(data[starting_offset: length + starting_offset]):
        if i % xor_switch_step == 0:
            offset_xor = 0     
        new_data += chr(ord(c) ^ ord(data_copy[address_xor+offset_xor]))
        offset_xor += 1

    #new_data = FixLabelDatatype_Float_To_Int(new_data)
    

    
    new_data_2 = ""
    for c in new_data[starting_offset_2:length_2+starting_offset_2]:
        new_data_2 += chr(255 - ord(c))
    #new_data_2 = FixLabelDatatype_Float_To_Int(new_data_2)

    new_data_3 = ""
    for c in new_data_2[starting_offset_3: length_3+starting_offset_3]:
        new_data_3 += chr(ord(c) ^ xor_value)
    new_data_3 = FixLabelDatatype_Float_To_Int(new_data_3)
    SaveData(new_data_3, "new")





# MultiStage_RaknetProtector
'''
f_name = "RakNet protector"
length = 143
starting_offset = 299

length_2 = 84
starting_offset_2 = 494
xor_value_2 = 255 - 51

length_3 = 182
starting_offset_3 = 850

length_4 = 287
starting_offset_4 = 21740
xor_value_4 = 37

length_5 = 532
starting_offset_5 = 20665

length_6 = 814
starting_offset_6 = 19650
xor_value_6 = 53
'''

def MultiStage_RaknetProtector():
    data = GetData()
    new_data = list(data)
    for i, c in enumerate(data[starting_offset:length + starting_offset]):
        new_data[i+starting_offset] = chr(255 - ord(c))

    for i, c in enumerate(data[starting_offset_2:length_2 + starting_offset_2]):
        new_data[i+starting_offset_2] = chr(ord(c) ^ xor_value_2)

    for i, c in enumerate(data[starting_offset_3:length_3 + starting_offset_3]):
        new_data[i+starting_offset_3] = chr(255 - ord(c))

    for i, c in enumerate(data[starting_offset_4:length_4 + starting_offset_4]):
        new_data[i+starting_offset_4] = chr(ord(c) ^ xor_value_4)

    for i, c in enumerate(data[starting_offset_5:length_5 + starting_offset_5]):
        new_data[i+starting_offset_5] = chr(255 - ord(c))

    for i, c in enumerate(data[starting_offset_6:length_6 + starting_offset_6]):
        new_data[i+starting_offset_6] = chr(ord(c) ^ xor_value_6)

    SaveData("".join(new_data), "new")




# Admin_Mode_Thing
'''
f_name = "admin_mode"
'''   

def Admin_Mode_Thing():
    data = GetData()
    new_data = []
    data_copy = data
    for i, c in enumerate(data_copy):
        if i%2 == 0 and i < len(data)-2:
            new_data.append(data_copy[i+1])
            new_data.append(chr(255 - ord(data_copy[i])))

    SaveData("".join(new_data), "new")



# Parazitas thing
'''
f_name = "Decrypt"
length = 592
starting_offset = 13
xor_value = 255 - 106

length_2 = 231
starting_offset_2 = 13
xor_switch_step = 16
address_xor = 244
'''

def ParazitasThing():
    data = GetData()
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)
    #new_data = FixLabelDatatype_Float_To_Int(new_data)
    new_data_2 = ""
    data_copy = new_data
    for i, c in enumerate(new_data[starting_offset_2: length_2 + starting_offset_2]):
        if i % xor_switch_step == 0:
            offset_xor = 0     
        new_data_2 += chr(ord(c) ^ ord(data_copy[address_xor+offset_xor]))
        offset_xor += 1
    
    SaveData(new_data_2, "new")
    return

'''
f_name = "time"
starting_offset = 7
length = 27215
xor_value = 255 - 109
'''
def YCE_Time(): # couldn't make it
    data = GetData()
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)

    SaveData(new_data, "new")
    
'''
f_name = "mokinys98"
starting_offset = 13
length = 7145
xor_switch_step = 16
address_xor = 7158

starting_offset_2 = 13
length_2 = 6861

starting_offset_3 = 13
length_3 = 6578
xor_value_3 = 103
'''
def Mokinys():
    data = GetData()
    #new_data = FixLabelDatatype_Float_To_Int(data)
    #SaveData(new_data, "fixed")

    new_data = ""
    offset_xor = 0
    for i, c in enumerate(data[starting_offset: length + starting_offset]):
        if i % xor_switch_step == 0:
            offset_xor = 0     
        new_data += chr(ord(c) ^ ord(data[address_xor+offset_xor]))
        offset_xor += 1

    new_data_2 = ""
    for i, c in enumerate(new_data[starting_offset_2: length_2 + starting_offset_2]): 
        new_data_2 += chr(255 - ord(c))

    new_data_3 = ""
    for i, c in enumerate(new_data_2[starting_offset_2: length_2 + starting_offset_2]): 
        new_data_3 += chr(ord(c) ^ xor_value_3)
        
    SaveData(FixLabelDatatype_Float_To_Int(new_data_3), "new")


'''
f_name = "AutoVartojimas"
starting_offset = 13
length = 22186
xor_value = 256 - 123

starting_offset_2 = 13
length_2 = 21902
xor_value_2 = 255

starting_offset_3 = 13
length_3 = 21541
address_xor_3 = 21554
xor_switch_step_3 = 16
'''

def AV():
    data = GetData()
    
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)
        
    new_data_2 = ""
    for i in range(length_2):
        new_data_2 += chr(ord(new_data[starting_offset_2 + i]) ^ xor_value_2)

    new_data_3 = ""
    for i, c in enumerate(new_data_2[starting_offset_3: length_3 + starting_offset_3]):
        if i % xor_switch_step_3 == 0:
            offset_xor_3 = 0     
        new_data_3 += chr(ord(c) ^ ord(new_data_2[address_xor_3+offset_xor_3]))
        offset_xor_3 += 1
        
    new_data_3 = FixLabelDatatype_Float_To_Int(new_data_3)   
    SaveData(new_data_3, "new")

'''
f_name = "iskvietimai"
starting_offset = 13
length = 34013
xor_value = 256 - 59

starting_offset_2 = 13
length_2 = 33729
xor_value_2 = 255

starting_offset_3 = 13
length_3 = 33368
address_xor_3 = 33381
xor_switch_step_3 = 16
'''


def Isk():
    data = GetData()
        
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)

    new_data_2 = ""
    for i in range(length_2):
        new_data_2 += chr(ord(new_data[starting_offset_2 + i]) ^ xor_value_2)
        
    
    
    new_data_3 = ""
    offset_xor_3 = 0
    for i, c in enumerate(new_data_2[starting_offset_3: length_3 + starting_offset_3]):
        if i % xor_switch_step_3 == 0:
            offset_xor_3 = 0     
        new_data_3 += chr(ord(c) ^ ord(new_data_2[address_xor_3+offset_xor_3]))
        offset_xor_3 += 1

    new_data_3 = FixLabelDatatype_Float_To_Int(new_data_3)
        
    SaveData(new_data_3, "new")

'''
f_name = "fps booster"
starting_offset = 39
length = 1407
xor_value = 255
'''

'''
starting_offset_2 = 7
length = 1214
xor_value = 255
'''


def Fps_Booster():
    data = GetData()
        
    new_data = []         

    data_copy = data
    for i in range(length):
        if i%2 == 0 and i < len(data)-2:
            new_data.append(data_copy[i+1])
            new_data.append(chr(255 - ord(data_copy[i])))
            
        #if i%2 == 1:
        #    data_copy[i] = chr(ord(data[starting_offset + i]) ^ xor_value)
        #else:
        #    data_copy[i] = data[starting_offset + i]
    
    


    #d = [(b if i%2==0 else str(hex(int(b,16)^255))[2:]) for i,b in enumerate(data.split()[1:])]
        
    SaveData("".join(new_data), "new_2modXor")

'''
f_name = "bot"
starting_offset = 13
length = 34711
xor_value = 256 - 120

starting_offset_2 = 13
length_2 = 34290
xor_value_2 = 255

starting_offset_3 = 13
length_3 = 33929
address_xor_3 = 33942
xor_switch_step_3 = 16
'''

def bot_miner666():
    data = GetData()
    SaveData(FixLabelDatatype_Float_To_Int(data), "fixed")

    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)

    new_data_2 = ""
    for i in range(length_2):
        new_data_2 += chr(ord(new_data[starting_offset_2 + i]) ^ xor_value_2)


    new_data_3 = ""
    offset_xor_3 = 0
    for i, c in enumerate(new_data_2[starting_offset_3: length_3 + starting_offset_3]):
        if i % xor_switch_step_3 == 0:
            offset_xor_3 = 0     
        new_data_3 += chr(ord(c) ^ ord(new_data_2[address_xor_3+offset_xor_3]))
        offset_xor_3 += 1


    SaveData(FixLabelDatatype_Float_To_Int(new_data_3), "new") 


'''
f_name = "legitchristmas"

starting_offset = 39
length = 27418

starting_offset_2 = 39
length_2 = 27217
xor_value_2 = 132

starting_offset_3 = 7
length_3 = 27013
'''



def xor(data, xor_value, starting_offset, length):
    new_data = ""
    for i in range(length):
        new_data += chr(ord(data[starting_offset + i]) ^ xor_value)
    return new_data


def  legitchristmas():
    data = GetData()
    new_data = ""
    c = ""
    for i in range(length):
        if i%2 == 1:
            c = chr(256 + ~ord(data[starting_offset + i]))
        else:
            c = data[starting_offset + i]
        new_data += c
        

    new_data_2 = xor(new_data, 132, 39, 27217)
    
    new_data_3 = ""
    data_copy = new_data_2[starting_offset_3 : length_3 + starting_offset_3]
    for i, c in enumerate(data_copy):
        if i%2 == 0 and i < length_3-1:
            new_data_3 += data_copy[i+1] + data_copy[i]
        
    SaveData(new_data_3, "new")


'''
f_name = "probably_final"
starting_offset = 0
length = 19857
xor_value = 255
'''

def Spextron_shit():
    data = GetData()
    data = xor(data, xor_value, starting_offset, len(data)-1)
    SaveData(data, "new")


'''
f_name = "For Monday"
starting_offset = 39
length = 17790
'''

def kazkaS():
    data = GetData()
    
    new_data = ""
    c = ""
    for i in range(length):
        if i%2 == 1:
            c = chr(256 + ~ord(data[starting_offset + i]))
        else:
            c = data[starting_offset + i]
        new_data += c
    SaveData(new_data, "new")


'''
f_name = "GameSpeed"
part_xor = "F8"
pause_cleo_bytes = "9F 0A 03 1F 00 DE 0B 03 1F 00"
'''

def FYP_2():
    data = GetData()
    SaveData(FixLabelDatatype_Float_To_Int(data), "fixed")
    SaveData(FixLabelDatatype_Float_To_Int(xor(data, int(part_xor,16), 0, len(data))), "xored_fixed")
    
    with open("pause_cleo_xored_" + part_xor + "_bytes.txt", "a+") as f:
        f.write(" ".join(["{:0X}".format((int(c,16) ^ int(part_xor, 16))) for c in pause_cleo_bytes.split(" ")]))
        
#FYP_2()

# 7C xor
# xored part responsible for resetting the mod:
# 8C 0A 03 00 00 04 01 03 02 00 04 00 0A 00 03
# offset x638 in x699 long file


'''
f_name = "FPS"
starting_offset = 13
length = 45376
initial_limiter = 16 
initial_limiter_starting_offset = 45389

starting_offset_2 = 13
length_2 = 45093
xor_value_2 = 256-117
'''

def FPS():
    data = GetData()
    data = FYP_XOR_CrossSided(data, starting_offset, length, initial_limiter, initial_limiter_starting_offset)
    data = FixLabelDatatype_Float_To_Int(data)
    

    data = FixLabelDatatype_Float_To_Int(xor(data, xor_value_2, starting_offset_2, length_2))
    SaveData(data, "new")
    






'''
f_name = "CruiseControl"
length = 23899
starting_offset = 0
'''

def CruiseControl():
    data = GetData()

    data = xor(data, 70, starting_offset, length)
    
    new_data = ""
    for i in range(length):
        if i%2 == 0 and i < length-1:
            new_data += data[i+1] + data[i]
    c = ''
    for i in range(length-1):
        if i%2 == 1:
            c = chr(256 + ~ord(new_data[starting_offset + i]))
        else:
            c = new_data[starting_offset + i]
        data += c
    SaveData(data, "new")


#CruiseControl()












