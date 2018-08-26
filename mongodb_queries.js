/* Check all tests */
db.getCollection('tests').aggregate([
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        "test": true,
        "begin": true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "result": true,
        "_id": false
    }
},
{
    "$out": "all-test-results"
}
])


/* Get average download/upload speeds */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "tcps4",
        "result.443": { $exists: true }
    }
}
,
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "result": true,
        "_id": false,
        "download_80" : {
            $divide: [ {
                $divide: ["$result.80.download.bytes","$result.80.download.duration_ms"]
            },125]
        },
        "upload_80" : {
            $divide: [ {
                $divide: ["$result.80.upload.bytes","$result.80.upload.duration_ms"]
            },125]
        },
        "download_443" : {
            $divide: [ {
                $divide: ["$result.443.download.bytes","$result.443.download.duration_ms"]
            },125]
        },
        "upload_443" : {
            $divide: [ {
                $divide: ["$result.443.upload.bytes","$result.443.upload.duration_ms"]
            },125]
        },
        "download_6881" : {
            $divide: [ {
                $divide: ["$result.6881.download.bytes","$result.6881.download.duration_ms"]
            },125]
        },
        "upload_6881" : {
            $divide: [ {
                $divide: ["$result.6881.upload.bytes","$result.6881.upload.duration_ms"]
            },125]
        },
        "download_48123" : {
            $divide: [ {
                $divide: ["$result.48123.download.bytes","$result.48123.download.duration_ms"]
            },125]
        },
        "upload_48123" : {
            $divide: [ {
                $divide: ["$result.48123.upload.bytes","$result.48123.upload.duration_ms"]
            },125]
        }
    }
},
    {
    "$out": "tcps4-test-results"
}
]);

/* Process mm7 results */

db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "mm7",
        "result.48123": { $exists: true }
    }
}
,
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "download_80" : {
            $divide: [ {
                $divide: ["$result.80.download.bytes","$result.80.download.duration_ms"]
            },125]
        },
        "upload_80" : {
            $divide: [ {
                $divide: ["$result.80.upload.bytes","$result.80.upload.duration_ms"]
            },125]
        },
        "download_48123" : {
            $divide: [ {
                $divide: ["$result.48123.download.bytes","$result.48123.download.duration_ms"]
            },125]
        },
        "upload_48123" : {
            $divide: [ {
                $divide: ["$result.48123.upload.bytes","$result.48123.upload.duration_ms"]
            },125]
        }
    }
},
    {
    "$out": "mm7-test-results"
}
]);



/* voip7 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "voip7",
        "result.statistics": { $exists: true },
        "result.statistics": {
            $size: 2
        }
    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false
    }
},
{
    "$unwind": "$result.statistics"
},
{
    $match: {
        "result.statistics.src_port" : 2222
    }
},
{
    $project: {
         "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "jitter_ms_max" : "$result.statistics.jitter_ms_max",
        "jitter_ms_mean" : "$result.statistics.jitter_ms_mean",
        "delta_ms_max" : "$result.statistics.delta_ms_max",
        "loss_percent" : "$result.statistics.loss_percent",
        "loss_packets" : "$result.statistics.loss_packets",
    }
},
    {
    "$out": "voip7-test-results"
}
]);


/* tcp4 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "tcp4",
        "result": { $exists: true },

    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "80_ping_client_mean": "$result.80.ping_client_mean",
        "80_ping_client_median": "$result.80.ping_client_mean",
        "80_ping_server_mean": "$result.80.ping_server_mean",
        "80_ping_server_median": "$result.80.ping_server_median",
        "80_ttl_source_mean": "$result.80.ttl_source_mean",
        "80_ttl_source_median": "$result.80.ttl_source_median",
        "220_ping_client_mean": "$result.220.ping_client_mean",
        "220_ping_client_median": "$result.220.ping_client_mean",
        "220_ping_server_mean": "$result.220.ping_server_mean",
        "220_ping_server_median": "$result.220.ping_server_median",
        "220_ttl_source_mean": "$result.220.ttl_source_mean",
        "220_ttl_source_median": "$result.220.ttl_source_median",
        "443_ping_client_mean": "$result.443.ping_client_mean",
        "443_ping_client_median": "$result.443.ping_client_mean",
        "443_ping_server_mean": "$result.443.ping_server_mean",
        "443_ping_server_median": "$result.443.ping_server_median",
        "443_ttl_source_mean": "$result.443.ttl_source_mean",
        "443_ttl_source_median": "$result.443.ttl_source_median",
        "554_ping_client_mean": "$result.554.ping_client_mean",
        "554_ping_client_median": "$result.554.ping_client_mean",
        "554_ping_server_mean": "$result.554.ping_server_mean",
        "554_ping_server_median": "$result.554.ping_server_median",
        "554_ttl_source_mean": "$result.554.ttl_source_mean",
        "554_ttl_source_median": "$result.554.ttl_source_median",
        "1725_ping_client_mean": "$result.1725.ping_client_mean",
        "1725_ping_client_median": "$result.1725.ping_client_mean",
        "1725_ping_server_mean": "$result.1725.ping_server_mean",
        "1725_ping_server_median": "$result.1725.ping_server_median",
        "1725_ttl_source_mean": "$result.1725.ttl_source_mean",
        "1725_ttl_source_median": "$result.1725.ttl_source_median",
        "5060_ping_client_mean": "$result.5060.ping_client_mean",
        "5060_ping_client_median": "$result.5060.ping_client_mean",
        "5060_ping_server_mean": "$result.5060.ping_server_mean",
        "5060_ping_server_median": "$result.5060.ping_server_median",
        "5060_ttl_source_mean": "$result.5060.ttl_source_mean",
        "5060_ttl_source_median": "$result.5060.ttl_source_median",
        "6881_ping_client_mean": "$result.6881.ping_client_mean",
        "6881_ping_client_median": "$result.6881.ping_client_mean",
        "6881_ping_server_mean": "$result.6881.ping_server_mean",
        "6881_ping_server_median": "$result.6881.ping_server_median",
        "6881_ttl_source_mean": "$result.6881.ttl_source_mean",
        "6881_ttl_source_median": "$result.6881.ttl_source_median",
        "8333_ping_client_mean": "$result.8333.ping_client_mean",
        "8333_ping_client_median": "$result.8333.ping_client_mean",
        "8333_ping_server_mean": "$result.8333.ping_server_mean",
        "8333_ping_server_median": "$result.8333.ping_server_median",
        "8333_ttl_source_mean": "$result.8333.ttl_source_mean",
        "8333_ttl_source_median": "$result.8333.ttl_source_median",
        "48123_ping_client_mean": "$result.48123.ping_client_mean",
        "48123_ping_client_median": "$result.48123.ping_client_mean",
        "48123_ping_server_mean": "$result.48123.ping_server_mean",
        "48123_ping_server_median": "$result.48123.ping_server_median",
        "48123_ttl_source_mean": "$result.48123.ttl_source_mean",
        "48123_ttl_source_median": "$result.48123.ttl_source_median"

    }
},
    {
    "$out": "tcp4-test-results"
}
]);


/* UDP4 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "udp4",
        "result.48123": { $exists: true },

    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "1725_ping_client_mean": "$result.1725.ping_client_mean",
        "1725_ping_client_median": "$result.1725.ping_client_mean",
        "1725_ping_server_mean": "$result.1725.ping_server_mean",
        "1725_ping_server_median": "$result.1725.ping_server_median",
        "1725_ttl_source_mean": "$result.1725.ttl_source_mean",
        "1725_ttl_source_median": "$result.1725.ttl_source_median",
        "5060_ping_client_mean": "$result.5060.ping_client_mean",
        "5060_ping_client_median": "$result.5060.ping_client_mean",
        "5060_ping_server_mean": "$result.5060.ping_server_mean",
        "5060_ping_server_median": "$result.5060.ping_server_median",
        "5060_ttl_source_mean": "$result.5060.ttl_source_mean",
        "5060_ttl_source_median": "$result.5060.ttl_source_median",
        "6881_ping_client_mean": "$result.6881.ping_client_mean",
        "6881_ping_client_median": "$result.6881.ping_client_mean",
        "6881_ping_server_mean": "$result.6881.ping_server_mean",
        "6881_ping_server_median": "$result.6881.ping_server_median",
        "6881_ttl_source_mean": "$result.6881.ttl_source_mean",
        "6881_ttl_source_median": "$result.6881.ttl_source_median",
        "9987_ping_client_mean": "$result.9987.ping_client_mean",
        "9987_ping_client_median": "$result.9987.ping_client_mean",
        "9987_ping_server_mean": "$result.9987.ping_server_mean",
        "9987_ping_server_median": "$result.9987.ping_server_median",
        "9987_ttl_source_mean": "$result.9987.ttl_source_mean",
        "9987_ttl_source_median": "$result.9987.ttl_source_median",
        "48123_ping_client_mean": "$result.48123.ping_client_mean",
        "48123_ping_client_median": "$result.48123.ping_client_mean",
        "48123_ping_server_mean": "$result.48123.ping_server_mean",
        "48123_ping_server_median": "$result.48123.ping_server_median",
        "48123_ttl_source_mean": "$result.48123.ttl_source_mean",
        "48123_ttl_source_median": "$result.48123.ttl_source_median"
    }
},
    {
    "$out": "udp4-test-results"
}
]);


/* SYN4 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "syn4",
        result: {$exists: true},
        "result.answers": {$lt:200}
    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "answers" : "$result.answers"
    }
},
{
    "$out": "syn4-test-results"
}
]);


/* SYN4 Alle  */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "syn4",
        result: {$exists: true}
    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "answers" : "$result.answers"
    }
},
{
    "$out": "syn4-test-results-all"
}
]);



/* DNS7 */

db.getCollection('tests').aggregate(
[
{
    "$match" : {
        $or: [
            { test: "ndns7" }, {test: "bdns7"}
        ],
        result: {$exists: true}

    }
},
{
    $unwind: "$result.requests"
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "host" : "$result.requests.host",
        "rcode" : "$result.requests.rcode",
        "duration_ms" : "$result.requests.duration_ms",
        "ttl" : "$result.requests.duration_ms",
        "nameservers" : {
            $size: {
                $ifNull: ["$result.requests.nameservers",[]]
            }
        },
        "entries" : {
            $size:{
                $ifNull: ["$result.requests.entries",[]]
            }
        }

        ,
        "first_entry" : {
            $arrayElemAt : ["$result.requests.entries", 0]
        }
    }
},
    {
    "$out": "dns7-test-results"
}
]);


/* CM7, HTTP7, VS7 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        $or: [
            { test: "cm7" }, { test: "http7"}, {test: "vs7"}
        ],
        result: {$exists: true}

    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        matches: { $size : "$result.matches" },
        mismatches: {$size: "$result.mismatches" },
        leftover: {$size: "$result.leftover" }
    }

},
{
    $match: {
        $or : [
        {
            mismatches: {$gt:0}
        },
        {
            leftover: {$gt:0}
        }
        ]
        }
}]);

db.getCollection('tests').aggregate(
[
{
    "$match" : {
        $or: [
            { test: "cm7" }, { test: "http7"}, {test: "vs7"}
        ],
        result: {$exists: true}

    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        matches: { $size : "$result.matches" },
        mismatches: {$size: "$result.mismatches" },
        leftover: {$size: "$result.leftover" }
    }

},
{
    $match: {
        $or : [
        {
            mismatches: {$gt:0}
        },
        {
            leftover: {$gt:0}
        }
        ]
	}
}
]);




/* TLS4 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        $or: [
            { test: "tls4" }
        ],
        result: {$exists: true},
        "result.mismatches": {$exists:true}

    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
    }

}
]);


/* POP37 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        $or: [
            { test: "pop37" }
        ],
        result: {$exists: true},
        $or: [
        {"result.110.invalid_address_received": false},
        {"result.8110.invalid_address_received": false}
        ]
    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
    }

}

]);


/* STLS7/SMTP7 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        $or: [
            { test: "smtp7" }, { test: "stls7" }
        ],
        result: {$exists: true}, 
        $or: [
        {"result.25.starttls_client_received": false},
        {"result.25.starttls_server_received": false},
        {"result.25.content_integrity": false}
        ]
    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
    }

}
]);


/* TRAC3 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "trac3",
        result: {$exists: true}

    }
},
{
    $unwind: "$result.requests"
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        result : true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        "_id": false,
        "host" : "$result.requests.host",
        "entries" : {
            $size:{
                $ifNull: ["$result.requests.result",[]]
            }
        }

        ,
        "target_ip" : {
            $arrayElemAt : ["$result.requests.result", -1]
        },
        "asdf" : "$target_ip.ip"
    }
},
{
    $project: {
        "test_uuid" : "$test_uuid",
        "begin": "$begin",
        "client_uuid": "$client_uuid",
        "test" : "$test",
        "result" : "$result",
        "has_result" : "$has_result",
        "entries" : "$entries",
        "target_ip" : "$target_ip.ip",
        "target_ip_hop" : "$target_ip.hop",
        "host" : "$host"
    }
},
    {
    "$out": "trac3-test-results"
}
])


/* OONI7 */
db.getCollection('tests').aggregate(
[
{
    "$match" : {
        test: "ooni7",
        "result.results": {$exists: true}
    }
},
{
    "$project": {
        "client_uuid": {
            "$substr" : ["$client_uuid",0,2]
        },
        "test_uuid": true,
        test: true,
        "begin": true,
        "has_result" : {
            "$cmp": ["$result",null]
        },
        ooni_results: "$result.results",
        "_id": false,
    }

},
    {
    "$out": "ooni7-test-results"
}
]);

