A = 5
import math
def algo(i):
    # print(i , "--> " ,  (A*i) / (A+i))
    print(i , "--> " ,  A*max(1 , math.log2(i/3600)))
for i in range(1 , 172800 , 1000):
    algo(i)