CC	=	gcc
CFLAGS	=	-Os -I/usr/include
DEST	=	/usr/bin
LDFLAGS	=	-L/usr/lib -lssl -lcrypto
OBJS	=	main.o urlenc.o session.o extract.o
OBJS	+=	base64.o hmac-sha1.o memxor.o sha1.o twilib.o parson.o
PROGRAM	=	simplestream

all:		$(PROGRAM)

$(PROGRAM):	$(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM)

.c.o:	$<
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f *.o *~ $(PROGRAM)