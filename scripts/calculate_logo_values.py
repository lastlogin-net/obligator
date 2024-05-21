import math
import sys

r = int(sys.argv[1])
angle = int(sys.argv[2])

circ = 2*math.pi*r

stroke_offset = circ / 4

stroke_dasharray = (angle / 360) * circ

val = stroke_dasharray
print('stroke-dasharray="{} {}"'.format(stroke_dasharray, circ - stroke_dasharray))
print("stroke-offset: ", stroke_offset)
