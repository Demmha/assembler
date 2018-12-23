def formating(filename):
    with open(filename) as f:
        a = f.readlines()
    addr = 0
    out2 = open('out2.txt', 'w')
    for i in a:
        out2.writelines(str(addr) + ": " + i)
        addr += 1
        
filename = 'out.txt'
formating(filename)