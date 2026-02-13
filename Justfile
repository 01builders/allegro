# Justfile for tempo-hackathon

# Default task
default: build

# Build the project
build:
    cargo build

# Build in release mode
release:
    cargo build --release

# Run the project
run:
    cargo run

# Run in release mode
run-release:
    cargo run --release

# Run tests
test:
    cargo test

# Run all workspace tests and print discovered test count
test-all:
    @count=$(cargo test --workspace -- --list 2>/dev/null | awk '/: test$/{n++} END{print n+0}'); \
    echo "Discovered $count tests"; \
    cargo test --workspace

# Check the project (faster than build)
check:
    cargo check

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Clean build artifacts
clean:
    cargo clean

# Run CI checks (format, lint, test)
ci:
    cargo fmt -- --check
    cargo clippy -- -D warnings
    cargo test
