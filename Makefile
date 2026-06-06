.PHONY: build dev clean dataset check

build:
	wasm-pack build crates/parser --target web --out-dir ../../web/pkg

dev:
	wasm-pack build crates/parser --target web --out-dir ../../web/pkg --dev

clean:
	cd crates/parser && cargo clean
	rm -rf web/pkg

check:
	cd crates/parser && cargo check

dataset:
	python3 generate-dataset.py
