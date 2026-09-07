INCLUDES = -Isrc -Isrc/legacy -Isrc/bitslice/common -Isrc/bitslice/v7 -Isrc/bitslice/v8 -Isrc/bitslice/v9
SOURCE = src/lmcrack.cpp

lmcrack:
	g++ $(INCLUDES) -Wall -O3 -fomit-frame-pointer -funroll-all-loops $(SOURCE) -olmcrack -lpthread
sse:
	g++ $(INCLUDES) -Wall -DSSE2 -msse2 -O3 -fomit-frame-pointer -funroll-all-loops $(SOURCE) -olmcrack -lpthread
sse2: sse

avx:
	g++ $(INCLUDES) -Wall -DAVX2 -mavx2 -O3 -fomit-frame-pointer -funroll-all-loops $(SOURCE) -olmcrack -lpthread
avx2: avx

avx512:
	g++ $(INCLUDES) -Wall -DAVX512 -mavx512f -O3 -fomit-frame-pointer -funroll-all-loops $(SOURCE) -olmcrack -lpthread

arm64:
	g++ $(INCLUDES) -Wall -DLMCRACK_NEON -O3 -mcpu=native -flto -fomit-frame-pointer $(SOURCE) -olmcrack -lpthread

arm64-pair256:
	g++ $(INCLUDES) -Wall -DLMCRACK_NEON -DLMCRACK_PAIR256 -O3 -mcpu=native -flto -fomit-frame-pointer $(SOURCE) -olmcrack -lpthread

arm64-pair64:
	g++ $(INCLUDES) -Wall -DLMCRACK_NEON -DLMCRACK_PAIR64 -O3 -mcpu=native -flto -fomit-frame-pointer $(SOURCE) -olmcrack -lpthread

clean:
	rm -rf *.o lmcrack
