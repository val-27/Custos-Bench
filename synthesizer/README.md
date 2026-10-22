# synthesizer

Generates the `corpus/` consumed by `custos-bench`.

```bash
python3 generate_all.py
python3 generate_all.py --imagenet-dir /data/imagenet/val
```

Each payload is written twice:

- `*.pb` — raw protobuf, no gRPC frame (what `custos-bench` sends)
- `*.grpc` — 5-byte uncompressed gRPC frame prepended (offline tests)

`corpus/manifest.json` indexes category, expected admission result, and size.
