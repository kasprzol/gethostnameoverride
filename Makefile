
CPP=g++
CPP_OPTS=--std=c++11 -fPIC -shared -O2 -g
LIBS=-ldl

all: hosts_override.so

hosts_override.so: gethostoverride.c
	$(CPP) $< -o $@ $(CPP_OPTS) $(LIBS)

clean:
	rm hosts_override.so
