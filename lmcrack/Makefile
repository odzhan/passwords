lmcrack:
	g++ -Wall -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread
sse:
	g++ -Wall -DSSE2 -msse2 -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread
sse2: sse

avx:
	g++ -Wall -DAVX2 -mavx2 -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread
avx2: avx

avx512:
	g++ -Wall -DAVX512 -mavx512f -O3 -fomit-frame-pointer -funroll-all-loops lmcrack.cpp -olmcrack -lpthread

clean:
	rm -rf *.o lmcrack
