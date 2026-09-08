# DimSense Test Environment — Security Onion Simulator

A single-node Elasticsearch 8.13.0 standing in for a Security Onion manager. It
holds synthetic Zeek connection logs with a planted C2 beacon so the Security
Onion connector and the full analysis pipeline can be exercised without a real
Security Onion deployment.

## Elasticsearch Connection
- Host: localhost
- Port: 9200
- Username: (none — security disabled for testing)
- Password: (none)
- SSL: disabled (plain HTTP)
- Version: 8.13.0
- Cluster name: dimsense-es-test

The DimSense connector assumes HTTPS for a bare hostname, as real Security
Onion requires. When it gets a plain-HTTP answer and no credentials were
supplied it falls back to `http://` automatically, so `"host": "localhost"`
works against this node. With credentials it refuses to downgrade; give the
host as `http://localhost` explicitly in that case.

## Two ways to run the node

Both use the same settings (`discovery.type=single-node`,
`xpack.security.enabled=false`, 512 MB heap) and the same port, so run only
one of them at a time.

### A. Local process (no Docker, no admin rights) — what is running now
Elasticsearch 8.13.0 was unpacked from the official zip into
`C:\Users\brion\dimsense-testenv\elasticsearch-8.13.0` and runs as a normal
user process with its bundled JDK. Config lives in
`config\elasticsearch.yml` and `config\jvm.options.d\heap.options`.

- Start (waits until the cluster answers): `powershell -File C:\Users\brion\dimsense-testenv\start_test_es.ps1`
- Stop: `powershell -File C:\Users\brion\dimsense-testenv\stop_test_es.ps1`
- Data and logs persist under the same folder between restarts. It does not
  start automatically after a reboot.

### B. Docker container (after the pending reboot)
Docker Desktop 4.90.0 is installed and the WSL2 features are enabled, but
Windows needs a restart before the Docker engine can start.

Create once:
```
docker run -d --name dimsense-es-test -p 9200:9200 ^
  -e "discovery.type=single-node" ^
  -e "xpack.security.enabled=false" ^
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" ^
  elasticsearch:8.13.0
```
Then load the data (see below). Afterwards:

- To restart after machine reboot: `docker start dimsense-es-test`
- To stop: `docker stop dimsense-es-test`

## Available Indices
- logs-zeek.conn-default (50,000 events, 5 days starting 2026-01-01)

It is a data stream, exactly as Security Onion 2.4 stores Zeek logs, backed by
a hidden `.ds-logs-zeek.conn-default-*` index. Elasticsearch 8's built-in
`logs-*-*` template requires this. The mapping comes from the index template
`dimsense-logs-zeek-conn` (pattern `logs-zeek.conn-*`). Query it by the data
stream name.

## Anomaly Window
- Events 32,000-38,000
- Time range: approximately 2026-01-04 (with the default seed: 2026-01-04T11:28:10Z to 2026-01-04T15:33:43Z)
- Pattern: C2 beacon to 185.220.101.50 — 3x event rate, 78% of connections to
  the C2 address, 30 new hosts in 10.0.1.0/24, ports collapse to 443/4444,
  short uniform durations and near-fixed payload sizes
- DimSense window: window 4 (events 32,768-40,959) when using 8,192-event windows
- Expected score: >= 10 with fields id.orig_h, id.resp_h, id.resp_p, proto,
  orig_bytes, resp_bytes, conn_state
- Verified 2026-09-08: score 11 in window 4, scores by window [0, 0, 0, 0, 11, 3]

## Connector request bodies

Test connection:

```json
{"host": "localhost", "port": 9200, "username": "", "password": "", "verify_ssl": false}
```

Pull the whole data set into a session:

```json
{
  "host": "localhost", "port": 9200, "username": "", "password": "", "verify_ssl": false,
  "index_pattern": "logs-zeek.conn-default",
  "start_time": "2026-01-01T00:00:00", "end_time": "2026-01-06T00:00:00",
  "max_rows": 50000, "time_field": "@timestamp"
}
```

Then `POST /analyze/{session_id}` and `POST /confirm-fields/{session_id}` with
`{"selected_fields": ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes", "conn_state"]}`.

## To regenerate and reload the data
```
python backend/tests/generate_zeek_data.py
```
The generator is seeded, so reloading produces the identical data set. It
deletes and recreates the data stream. Use `--dry-run --csv out.csv` to
produce the same events as a CSV without Elasticsearch, for example to compare
the CSV upload path with the connector path.
