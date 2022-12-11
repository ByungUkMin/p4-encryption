set size 1.5,1.5
set terminal postscript eps color solid "Helvetica-Bold" 32
set pointsize 3.0
set output 'aes_result.eps'

# legend info
#set key autotitle columnhead
set key left top Left
#set key off

# axis info
#set rmargin 5
#set xtics nomirror rotate by -45 scale 0
set xtics (1000,5000,10000,50000,100000)
set ytics auto
# set ytics 2e6
# set format y '%.s%c'
set grid ytics ls 3 lt 0
set grid xtics ls 3 lt 0

# line style
set style line 6   lt 6 lw 5 pt 6 
set style line 5   lt 5 lw 5 pt 5 
set style line 4   lt 4 lw 5 pt 4 
set style line 3   lt 3 lw 5 pt 3 
set style line 2   lt 2 lw 5 pt 2 
set style line 1   lt 1 lw 5 pt 1 

#set ytics auto nomirror
#set y2tics auto nomirror
#set logscale x
#set autoscale y
set xlabel "Number of Packets"
set ylabel "Execution Time (seconds)"
set logscale x 10
#set logscale y 10
set xrange[1000:100000]
set yrange[0:600]

# set xrange[1:3500]
# set yrange[1:2e4]

plot 'aes_rawdata.dat' using 1:2 ls 4 with linespoints t 'Switch without AES', '' using 1:3 ls 3 with linespoints t 'Switch with AES'
