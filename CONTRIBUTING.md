# Contributing

Thanks for your interest!

## Requirements
- C++20, portable.
- Keep dependencies minimal; rely on OpenSSL 3.x (libssl-dev).
- `make -j` should build cleanly (no errors). Reduce warnings when practical.

## Style
- Use `clang-format` (see `.clang-format`).
- Prefer **Conventional Commits** (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `test:`...).

## Tests (local smoke)
```bash
make -j$(nproc)
./bin/HippoFrog --generate-keys
./bin/HippoFrog --validate-keys
echo "test" > t.txt && ./bin/HippoFrog --encrypt t.txt && ./bin/HippoFrog --decrypt t.txt.hf
diff -q t.txt t.txt.dec
```
