# microTCP
A lightweight TCP implementation using UDP transport layer.

This is the class project for CS-335a (www.csd.uoc.gr/~hy335a/) for the
Fall 2017 semester.

## Build requirements
To build this project `cmake` is needed.

## Build instructions
```bash
mkdir build
cd build
cmake ..
make
```

## Run instructions
./bandwidth_test -s -m -p 8080 -f txt || server side
./bandwidth_test -m -a (ip) -p 8080 -f txt || client side 

45.153.183.199


