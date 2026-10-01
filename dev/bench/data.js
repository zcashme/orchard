window.BENCHMARK_DATA = {
  "lastUpdate": 1790840291727,
  "repoUrl": "https://github.com/zcashme/orchard",
  "entries": {
    "Orchard Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "julian.abraham@xaviers.edu.in",
            "name": "Julian Abraham",
            "username": "craftsoldier"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a5d81d2368b192e5beb442a704206fc85b6e8724",
          "message": "Merge pull request #9 from zcashme/port/0.16.0\n\nRebase ZNS fork onto upstream orchard 0.16.0",
          "timestamp": "2026-10-01T12:27:57+05:00",
          "tree_id": "fe480e25579b5b53b81792734a1d1a0b6e4bbea7",
          "url": "https://github.com/zcashme/orchard/commit/a5d81d2368b192e5beb442a704206fc85b6e8724"
        },
        "date": 1790840290321,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 1896761999,
            "range": "± 121662290",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 1890258526,
            "range": "± 4150039",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 2711310981,
            "range": "± 15206276",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 3529921535,
            "range": "± 30908766",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 15856684,
            "range": "± 76277",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 15877043,
            "range": "± 383915",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 18098440,
            "range": "± 131720",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 20406361,
            "range": "± 99998",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 877126,
            "range": "± 2983",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 78639,
            "range": "± 181",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 874049,
            "range": "± 47654",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 820620336,
            "range": "± 851995",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 8823779,
            "range": "± 31299",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 851487,
            "range": "± 2008",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 8794175,
            "range": "± 10906",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 825081,
            "range": "± 1077",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 44065859,
            "range": "± 82791",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 4188866,
            "range": "± 35517",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 43896938,
            "range": "± 121917",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 4050864,
            "range": "± 5512",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 88178781,
            "range": "± 114800",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 8348034,
            "range": "± 87993",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 87754476,
            "range": "± 109935",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 8080754,
            "range": "± 18029",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}