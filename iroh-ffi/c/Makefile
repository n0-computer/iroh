
build: iroh.h
	cargo build --release
	$(CC) main.c -o main -L ../target/release -l iroh -l pthread -l dl

iroh.h:
	cargo test --features c-headers -- generate_headers
	cp ../iroh.h iroh.h
