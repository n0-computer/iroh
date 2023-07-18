
build: iroh.h
	cargo build -p iroh-ffi --release
	$(CC) main.c -o main -L ../../target/release -l iroh -l pthread -l dl

iroh.h:
	cargo test -p iroh-ffi --features c-headers -- generate_headers
	cp ../iroh.h iroh.h
