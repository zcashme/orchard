window.BENCHMARK_DATA = {
  "lastUpdate": 1791725175973,
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
          "id": "6ffdf4ef8825b15b4e436252b6da4e0182ae5d74",
          "message": "Add typed ZNS commitment inputs (#11)",
          "timestamp": "2026-10-11T18:14:56+05:00",
          "tree_id": "c80f5326428ba3664d6672568b040465e55c965b",
          "url": "https://github.com/zcashme/orchard/commit/6ffdf4ef8825b15b4e436252b6da4e0182ae5d74"
        },
        "date": 1791725174524,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2272269412,
            "range": "± 99802624",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2266887164,
            "range": "± 5862301",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 3233600921,
            "range": "± 7583562",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 4226213738,
            "range": "± 39545238",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 18981247,
            "range": "± 121893",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 19009764,
            "range": "± 139500",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 21814476,
            "range": "± 142307",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 24654647,
            "range": "± 393306",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1045654,
            "range": "± 14850",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 94177,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1043658,
            "range": "± 18957",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 996181093,
            "range": "± 1018690",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 10530935,
            "range": "± 109691",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 1019955,
            "range": "± 5274",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 10513874,
            "range": "± 68528",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 988370,
            "range": "± 6698",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 52556148,
            "range": "± 208377",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 5005907,
            "range": "± 59543",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 52452389,
            "range": "± 689948",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 4852063,
            "range": "± 28048",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 105040968,
            "range": "± 1217532",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 9972805,
            "range": "± 26964",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 104828283,
            "range": "± 961939",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 9678749,
            "range": "± 22276",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}