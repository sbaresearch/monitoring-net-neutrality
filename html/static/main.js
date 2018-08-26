$(document).ready(function () {
    $(".test-tcps4").each(function () {
        console.log("start tcps4 graph");

        results = $("tr#result pre").html();
        results = JSON.parse(results);

        //for each port
        $.each(results, function (key, value) {
            //append line to table
            $("#results-table").append('<tr><td>Down ' + key + '</td><td><div style="height: 200px;" class="speed-curve-graph-download-' + key + '"></div><table class="table table-condensed speed-curve-table-download-' + key + '"></table></td></tr>');
            $("#results-table").append('<tr><td>Up ' + key + '</td><td><div style="height: 200px;" class="speed-curve-graph-upload-' + key + '"></div><table class="table table-condensed speed-curve-table-upload-' + key + '"></table></td></tr>');


            //call flot code
            drawSingleSpeedCurve("#results-table","download-{p}".replace("{p}", key), results[key].download.speed_curve);
            drawSingleSpeedCurve("#results-table","upload-{p}".replace("{p}", key), results[key].upload.speed_curve);
        });


    });
});


/**
 * draws a speed curve in the given area
 * @param {css-selektor} target the target-area. the curve is drawn in the child with class ".speed-curve-graph"
 * @param {json} data
 * @param {string} phase either 'download' or 'upload'
 */
function drawSingleSpeedCurve(target, phase, data) {
    //set width for flot
    $(target + " .speed-curve-graph-" + phase).css("width",$(target + " .speed-curve-graph-" + phase).width() + "px");
    var tableHtml = "";

    //smoothing-factor for exponential smoothing
    var alpha = 0.7;
    var conAlpha = 1-alpha;
    var minInterval = 175; //minimal difference in ms between data points
    var noTransferThreshold = 1400; //ms for which no transfer has to take place to be drawn as a gap in the graph

    //get data points from json-response from the controlserver
    var previousSpeed=data[0].bytes_total/data[0].time_elapsed;
    var previousData = 0;
    var previousTime = 0;
    var dDownload = [];

    //"preprocess" - if there are large gaps, fill them with artificial data points (#1117)
    var nData = [];
    for (var i=0;i<data.length;i++) {
        var timeDifference = data[i].time_elapsed - previousTime;
        if (timeDifference > (noTransferThreshold) && i > 0) {

            nData.push({
                time_elapsed: (data[i-1].time_elapsed + minInterval),
                bytes_total: (data[i-1].bytes_total)
            });
             nData.push({
                time_elapsed: (data[i-1].time_elapsed + 2*minInterval),
                bytes_total: (data[i-1].bytes_total)
            });
            nData.push({
                time_elapsed: (data[i].time_elapsed - minInterval),
                bytes_total: (data[i-1].bytes_total)
            });
        }
        nData.push(data[i]);
        previousTime = data[i].time_elapsed;
    }

    data = nData;
    previousTime = 0;

    for (var i = 0; i < data.length; ++i) {
        var dataDifference = data[i].bytes_total - previousData;
        var timeDifference = data[i].time_elapsed - previousTime;

        //only one point every 250 ms or data is way too late (120 sek)
        if (timeDifference < minInterval || data[i].time_elapsed > 120000) {
            continue;
        }

        var speed = dataDifference / timeDifference;
        if (speed > 0) { //no interpolation in a gap
            speed = speed*alpha + previousSpeed*conAlpha;
        }
        previousSpeed = speed;
        previousData = data[i].bytes_total;
        previousTime = data[i].time_elapsed;
        //do it logarithmic
        speed = log10(speed/125); //bytes/s ->
        dDownload.push([data[i].time_elapsed, speed,-2 ]); //byte : 128 = kilobit; mbit/sec = kbit/ms       //third parameter -2: fill until bottom of graph



        tableHtml += "<tr><td>" + (data[i].time_elapsed/1000).formatNumber(2) + " s</td>" +
                "<td>" + (dataDifference/timeDifference/125).formatNumber(getSignificantDigits(dataDifference/timeDifference/125)) + " Mbps</td>"+
                "<td>" + ODF.bytesFormatter(data[i].bytes_total) + "</td></tr>";
    }
    $(target + " .speed-curve-table-" + phase).append(tableHtml);
    tableHtml = "";


    var placeholder = $(target + " .speed-curve-graph-" + phase);

    //draw the plot
    var plot = $.plot(placeholder, [{
            data: dDownload,
            lines: {show: true, fill: true},
            color: "#00cc00"
        }
    ], {
        xaxis: {
            show: true,
            tickFormatter: function(v, xaxis) {

                    return (v/1000).toFixed(1) + " s";
            }
        },
        yaxis: {
            show: true,
            tickFormatter: function(v,axis) {
                //inverse function to log from above
                v = ((Math.pow(10,v)));
                //format <1mbps with 2 decimal points
                if (v>4) { return v.toFixed(0) + " Mbps"; } else { return v.toFixed(1) + " Mbps"; }
            },
            ticks: [-1,0,1,2,3], //ln(125), ln(1250), ln(12500)
            min: -1
        }
    });


}


function log10(val) {
  return Math.log(val) / Math.LN10;
}

/**
 * Formats a number
 * http://stackoverflow.com/questions/9318674/javascript-number-currency-formatting
 * @param {Number} decimals the number of decimal places
 * @param {String} thouSeperator the thousands seperator
 * @param {String} decSeperator the decimal seperator
 * @returns {String} the formatted number
 */
Number.prototype.formatNumber = function(decimals,thouSeperator,decSeperator) {
    //Standard values
    if (decimals === undefined) {
        decimals = 0;
    }
    if (thouSeperator === undefined) {
        thouSeperator = "";
    }
    if (decSeperator === undefined) {
        decSeperator = ".";
    }

    var n = this;

    if (decimals < 0) {
        var nDecimals = Math.abs(decimals);
        nDecimals = Math.pow(10,nDecimals);
        n = Math.round(n/nDecimals)*nDecimals;
        decimals = 0;
    }

    sign = n < 0 ? "-" : "",
    i = parseInt(n = Math.abs(+n || 0).toFixed(decimals)) + "",
    j = (j = i.length) > 3 ? j % 3 : 0;
    return sign + (j ? i.substr(0, j) + thouSeperator : "") + i.substr(j).replace(/(\d{3})(?=\d)/g, "$1" + thouSeperator) + (decimals ? decSeperator + Math.abs(n - i).toFixed(decimals).slice(2) : "");

};

var getSignificantDigits = function(number) {
        if (number > 100) {
            return -1;
        }
        else if (number >= 10) {
            return 0;
        }
        else if (number >= 1) {
            return 1;
        }
        else if (number >= 0.1) {
            return 2;
        }
        else  {
            return 3;
        }
    };


var ODF = new Object();
/**
 * Formats a bytes figure to one significant digit
 * @param {long} bytes
 * @returns {String} the formatted value
 */
ODF.bytesFormatter = function(bytes) {
    if (bytes === null)
        return null;
    var unit = "Bytes";
    if (bytes > 1000) {
        bytes = bytes/1000;
        unit = "KB";
    }
    if (bytes > 1000) {
        bytes = bytes/1000;
        unit = "MB";
    }
    return bytes.formatNumber(getSignificantDigits(bytes)) + "&nbsp;" + unit;

};