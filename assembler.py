from table import *
import re

stable = {} #global symbol table
ttable = [] #each code line and instr type
###################(code start here)################################
def filter_line(a, op=";"): #remove any comments
    idx = a.find(op)
    if idx == -1:
        return a
    elif idx == 0:
        return ''
    else:
        if op == ";":
            a = a[:(idx-1)]
        else:
            a = a[:idx]
    return a

def prepare_file(filename): #return array with only the code lines
    with open(filename) as f:
        a = f.readlines()
    a = map(filter_line, a) #remove comments using map from all lines   
    a = [ i.strip() for i in [ x for x in a ] ] #remove space
    a = list(filter(lambda x : x != '', a)) #remove empty elements    
    return a

def get_word(operands):

    w = 0 #num of words to be returned
    
    #remove comma if it exists and check the second operand
    op_1 = re.sub(',', '', operands[0])
    if len(operands) == 1:
        op_2 = '' 
    else:
        op_2 = operands[1]

    if re.match(r"([@]*[rR][0-7]|[@]*\([Rr][0-7]\)\+|[@]*\-\([Rr][0-7]\))", op_1):
        w = w
    elif re.match(r"#", op_1):  #indexed mode
        w += 1
    elif re.match(r"[@]*[\-]*[0-9]+\([Rr][0-7]\)", op_1):
        w += 1
    else:
        w += 1 

    if op_2 == '':
        return w

    if re.match(r"([@]*[rR][0-7]|[@]*\([Rr][0-7]\)\+|[@]*\-\([Rr][0-7]\))", op_2):
        w = w
    elif re.match(r"#", op_2):
        w += 1
    elif re.match(r"[@]*[\-]*[0-9]+\([Rr][0-7]\)", op_2):
        w += 1
    else:
        w += 1
        
    return w
        
def get_info(inp_line, address): 
    twop = r"[a-zA-Z][a-zA-Z][a-zA-Z]\s+.+,.+" #detect two operand instructions
    oneop = r"[a-zA-Z][a-zA-Z][a-zA-Z]\s+.+" #detect any branch or one operand instructions
    label = r"[a-zA-Z0-9]+[:]" #labels can be named anything but must be followed by :
    op_1 = r"[^bB][a-zA-Z][a-zA-Z]\s+.+" 
    var = r"[dD][eE][fF][iI][nN][eE]\s+.+\s+.+" #any Define variable
    nop = r"([Hh][lL][tT]|[nN][oO][pP])" #no operand instr
    # jump instructions to be added
    
    addr = 1 #value to be returned
    
    if re.match(twop, inp_line):
        operands = inp_line.split()
        del operands[0] #remove the instruction from the list 
        
        addr += get_word(operands) #calc num of words taken by each operand
        ttable.append((inp_line,"twop"))
    
    elif re.match(oneop, inp_line): #maybe jump or branch or one operand instr   #jumb to be added

        if re.search(op_1, inp_line): #one operand instr indeed
            operands = inp_line.split()
            del operands[0]
            
            addr += get_word(operands)
            ttable.append((inp_line, "oneop"))
        else: #else branch instr
            ttable.append((inp_line, "branch"))
            
    elif re.match(r"[bB][rR]\s+.+", inp_line): #for br instr
        ttable.append((inp_line, "branch"))
        
    elif re.match(var, inp_line):#Define variable found        
        var = inp_line.split() 
        #val = var[2] #what to do with the value of the variable??
        var = var[1]
        stable[var] = address #save the variable and its address in symbol table
        ttable.append((inp_line, "var"))

    elif re.match(nop, inp_line):
        ttable.append((inp_line, "nop"))

    elif re.match(label, inp_line):
        addr -= 1 #labels dont take address as in sample code
        inp_line = re.sub(':', '', inp_line)
        stable[inp_line] = address #save address of label in symbol table
        
    return addr

def to_binary(rkm, nbits): #signed int to binary
    return format(int(rkm), 'b').zfill(nbits)

def get_operand(operand, ref):#opcode of operand
    opcode = '' #
    sec = '' #for indexed or auto inc mode 
    if operand in stable:    #variable as operand
        addr = stable[operand] #get the address of variable
        opcode = el_table_el_gamed["x(r7)"] #get the opcode of indexed r7 a7la sho8l
        x = addr - (ref + 2) #address - updated pc
        sec = to_binary(x, 16)
        sec = sec.replace('-', '1') #if neg replace it with 1
    
    elif re.match(r"(#)([\-]*[0-9]+)", operand): #auto increment mode -> immediate value 
        val = re.sub('#', '', operand)
        opcode = el_table_el_gamed["(r7)+"]
        sec = to_binary(val, 16)
        sec = sec.replace('-', '1') #can be signed ?
    
    elif re.match(r"([@]*)([\-]*[0-9]+)(\([Rr][0-7]\))", operand): #indirect indexed
        here = re.match(r"([@]*)([\-]*[0-9]+)(\([Rr][0-7]\))", operand)
        first, x, second = here.groups()
        opcode = el_table_el_gamed[first + 'x' + second]
        sec = to_binary(x, 16)
        sec = sec.replace('-', '1')  
    
    else: #others
        if operand.lower() in el_table_el_gamed:
            opcode = el_table_el_gamed[operand.lower()]
        else:
            print("error: NO such operand ", operand)
        
    return opcode, sec
    
#jmp ?    
def get_branch(cline, pc):#branch label#
    cline = cline.split()
    instr = cline[0].lower()
    label = cline[1]
    opcode = ''
    
    if instr in el_table_el_gamed :
        opcode += el_table_el_gamed[instr]
    else :
        print("error: NO such instruction ", instr)
        
    if label in stable:
        address = stable[label]
        offset = address - (pc + 2) #offset = address of label - (pc + 2)  
        offset = to_binary(offset, 8)
        offset = offset.replace('-', '1')      
        opcode += offset
    else:
        print("error: NO such label ", label)
    
    return opcode
    

def get_opcode(cline, addr, cond): #opcode of line
    opcode = ''  #opcode of the line
    sec = '' #if it needs another word
    v_word = '' #any variable word
    
    cline = cline.split()
    instr = cline[0].lower()
    
    if instr in el_table_el_gamed: #el_table_el_gamed.keys()
        opcode += el_table_el_gamed[instr]
    else: 
        print("error: NO such instruction ", instr)
    
    op_1 = re.sub(',', '', cline[1])
    
    op_1, sec = get_operand(op_1, addr)
    opcode += op_1
    if sec != '':
        addr += 1
        v_word += '\n' + sec
        sec = ''
    
    if cond:
        op_2 = cline[2]

        op_2, sec = get_operand(op_2, addr)
        opcode += op_2    
        if sec != '':
            addr += 1
            v_word += '\n' + sec

    return opcode + v_word, addr #return opcode line/s and updated address
    
    
        
def yalla(outp): #get the opcode of instruction and the two operands with their addressing mode
    addr = 0
    for i in range(len(ttable)):
        
        cline = ttable[i][0] #code Line
        instr = ttable[i][1] #instruction
        
        if instr == "twop":
            machine_code, a_addr = get_opcode(cline, addr, True)
            addr = a_addr + 1
            outp.writelines(machine_code + '\n')
        
        elif instr == "oneop":
            machine_code, a_addr = get_opcode(cline, addr, False) 
            addr = a_addr + 1
            outp.writelines(machine_code + '\n')
            
        elif instr == "var": #if define var save val 
            var = cline.split() 
            val = var[2]
            val = to_binary(val, 16)
            val = val.replace('-', '1')
            addr += 1
            outp.writelines(val + '\n')
            
        elif instr == "branch":
            machine_code = get_branch(cline, addr)
            addr += 1
            outp.writelines(machine_code + '\n')
            
        elif instr == "nop": #no operand instr
            cline = cline.lower()
            if cline in el_table_el_gamed:
                machine_code = el_table_el_gamed[cline]
                outp.writelines(machine_code + '\n')
            else:
                print("error: NO such an instruction ", cline)
                    
            addr += 1
    
def assembler():
    inp_arr = []

    inputfile = 'inp.txt'
    outp = open('out.txt', 'w')
    
    inp_arr = prepare_file(inputfile)
    
    address = 0
    #now get the address of each code line
    for i in range(len(inp_arr)):
        outp.writelines(inp_arr[i] + "\t\t" + "address " + str(address) + '\n')
        address += get_info(inp_arr[i], address) #address to be used in saving variables address in symbol table
    yalla(outp)

assembler()