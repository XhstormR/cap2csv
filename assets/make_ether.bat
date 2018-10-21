@ echo off
type nul > ether.h
echo #ifndef CAP2CSV_ETHER_H > ether.h
echo #define CAP2CSV_ETHER_H >> ether.h
echo. >> ether.h
busybox awk "NR>27 && NR<106 {print >> \"ether.h\"}" print-ether.c
echo #endif //CAP2CSV_ETHER_H >> ether.h
