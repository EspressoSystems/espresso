#!/usr/bin/env sh
set -ev

function test_package() {
	cargo llvm-cov --no-report --profile=release-lto --all-features -p "$1" -- --test-threads=1
}

cargo llvm-cov clean --workspace # remove artifacts that may affect the coverage results
test_package address-book
test_package espresso-client
test_package espresso-core
test_package espresso-validator
test_package faucet
cargo llvm-cov report --profile=release-lto --lcov --output-path lcov.info # generate report without tests
