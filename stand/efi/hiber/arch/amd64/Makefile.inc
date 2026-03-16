.PATH: ${.CURDIR}/../loader/arch/${MACHINE}

SRCS+=	start.S

CFLAGS+=	-fPIC
LDFLAGS+=	-Wl,-znocombreloc
