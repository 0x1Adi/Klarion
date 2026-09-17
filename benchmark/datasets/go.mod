// Benchmark corpora are scan targets, not Klarion code, and some of them ship
// Go files. This makes the directory its own module, so `go build ./...`,
// `go test ./...` and `go vet ./...` in the repository skip every dataset.
module klarion-benchmark-datasets

go 1.25
