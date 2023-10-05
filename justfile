_:
  @just --list

## cross build x86-64 musl debug
#cross-build-x64-debug:
#  cross build --target x86_64-unknown-linux-musl

## cross build x86-64 musl release
#cross-build-x64:
#  cross build --target x86_64-unknown-linux-musl --release

# cross build x86-64 musl release(for openssl)
cross-build-x64-musl:
  docker run --rm -it \
  -v "$(echo $HOME)/.cargo_messense_rust-musl-cross_x86_64-musl_registry":/root/.cargo/registry/ \
  -v "$(pwd)":/home/rust/src \
  messense/rust-musl-cross:x86_64-musl \
  cargo build --release

# cross build x86-64 musl release(for openssl) 2
cross-build-x64-musl-2:
  docker run --rm -it \
  -v "$(echo $HOME)/.cargo/config":/root/.cargo/config \
  -v "$(echo $HOME)/.cargo_messense_rust-musl-cross_x86_64-musl_registry":/root/.cargo/registry/ \
  -v "$(pwd)":/home/rust/src \
  messense/rust-musl-cross:x86_64-musl \
  cargo build --release

# cross build x86-64 musl release(for openssl) 3
cross-build-x64-musl-3:
  docker run --rm -it \
  -v "$(echo $HOME)/.cargo/config":/root/.cargo/config \
  -v "$(echo $HOME)/.cargo_messense_rust-musl-cross_x86_64-musl_registry":/root/.cargo/registry/ \
  -v "$(pwd)":/volume \
  clux/muslrust \
  cargo build --release --target=x86_64-unknown-linux-musl

