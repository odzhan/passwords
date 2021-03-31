lmcrack:
	g++ -Wall -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread
sse:
	g++ -Wall -DSSE -msse2 -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread

avx:
	g++ -Wall -DAVX -mavx2 -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread

clean:
	rm -rf *.o lmcrack
