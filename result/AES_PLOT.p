set size 1.5,1.5
set terminal postscript eps color solid "Helvetica" 48
set output 'AESResult.eps'


#set key left top Left reverse
set key font ",32"

set format y '%.s%c'
set ytics 100
# set grid ytics ls 3
set ylabel "Execution Time (seconds)"

set boxwidth 0.9 relative
set style data histograms
set style histogram clustered gap 2

set offset -0.6,-0.6,0,0

set auto x
set yrange [0:600]
#plot for [COL=2:4:1] 'overheadresult.dat' using COL:xticlabels(1)
plot 'overheadresult.dat' using 3:xtic(1) title 'switch with AES' fillstyle empty lw 7, \
        'overheadresult.dat' using 2:xtic(1) title 'switch without AES' fillstyle solid 1.0 lw 7