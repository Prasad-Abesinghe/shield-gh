# set number of nodes
set opt(nn) 200

# set activity file
set opt(af) $opt(config-path)
append opt(af) /galle_ns2activity.tcl

# set mobility file
set opt(mf) $opt(config-path)
append opt(mf) /galle_mobility.tcl

# set start/stop time
set opt(start) 0.0
set opt(stop) 600.0

# set floor size
set opt(x) 3279.07
set opt(y) 3227.95
set opt(min-x) 402.01
set opt(min-y) 8.76

