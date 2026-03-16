
.include <bsd.init.mk>

PROG=		hiber.sym
INTERNALPROG=
WARNS?=		6

SRCS=	hiber.c \
	hiber_printf.c \
	libc.c \
	restore.c \
	self_reloc.c

.PATH: ${.CURDIR}/../loader
.PATH: ${.CURDIR}/../loader/arch/${MACHINE}
.PATH: ${.CURDIR}/../../common
.include "${.CURDIR}/../hiber/arch/${MACHINE}/Makefile.inc"

CFLAGS+=	-Wall
CFLAGS+=	-DEFI
CFLAGS+=	-I${SRCTOP}/stand/common
CFLAGS+=	-I${EFISRC}/include
CFLAGS+=	-I${EFISRC}/include/${MACHINE}
CFLAGS+=	-I${EDK2INC}

FILES+=	hiber.efi
FILESMODE_hiber.efi=	${BINMODE}

# use loader ldscript for now
LDSCRIPT=	${.CURDIR}/../loader/arch/${MACHINE}/${MACHINE}.ldscript
LDFLAGS+=	-Wl,-T${LDSCRIPT},-Bsymbolic,-znotext -pie
.if ${LINKER_TYPE} == "bfd" && ${LINKER_VERSION} >= 23400
LDFLAGS+=	-Wl,--no-dynamic-linker
.endif

.include <bsd.linker.mk>

CLEANFILES+=	${PROG}.efi

hiber.efi: ${PROG}
	@if ${NM} ${.ALLSRC} | grep ' U '; then \
		echo "Undefined symbols in ${.ALLSRC}"; \
		exit 1; \
	fi
	SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
	${EFI_OBJCOPY} -j .peheader -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame -j set_Xcommand_set \
		-j set_X${LOADER_INTERP}_compile_set \
		--output-target=${EFI_TARGET} ${.ALLSRC} ${.TARGET}

.include <bsd.prog.mk>
