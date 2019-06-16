# TLS
Make sure that the openssl library is pre-installed in your system.

Execute following commands:
i)g++ generate_cert.cpp -lssl -lcrypto

ii) g++ -o server server.cpp -lssl -lcrypto

iii) g++ -o client client.cpp -lssl -lcrypto

iv) ./a.out

v)./server 6669

vi)./client

Now you server-client chat application is ready :)
