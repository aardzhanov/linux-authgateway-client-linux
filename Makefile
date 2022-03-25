default:
	gcc authclient.c -o authclient -Wall

debug:
	gcc -g authclient.c -o authclient -Wall


clean:
	rm authclient