#!/usr/bin/env python

# Taken from: https://rotational.io/blog/speeding-up-go-tests/ this python script assists in parsing Golang JSON unit
# tests and sorting them by the amount of time taken
#
# To use, run Go unit tests via the following:
# go test -v -json -count 1 github.com/cloudnativelabs/kube-router/v2/cmd/kube-router/ github.com/cloudnativelabs/kube-router/v2/pkg/... >testing_output.json
#
# Then run this script via:
# build/test-scripts/unit_test_timing.py testing_output.json

import json
import sys

if __name__ == "__main__":
    tests = []

    with open(sys.argv[1], 'r') as f:
        for line in f:
            data = json.loads(line)
            if data['Action'] != 'pass':
                continue

            if 'Test' not in data:
                continue

            if data['Elapsed'] < 0.1:
                continue

            tests.append(data)

    tests.sort(key=lambda d: d['Elapsed'], reverse=True)
    for t in tests:
        print(f"{t['Elapsed']:0.3f}s\t{t['Package']} {t['Test']}")
