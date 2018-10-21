@ echo off

if exist cmake-build-123 rd /q /s cmake-build-123
if not exist cmake-build-123 md cmake-build-123
cd cmake-build-123
cmake .. -G "MinGW Makefiles"
mingw32-make install
cd ..

:: gcc readfile.c -s -static -I .\npcap-sdk\Include -L .\npcap-sdk\Lib\x64 -lwpcap
