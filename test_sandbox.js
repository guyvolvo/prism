
// String matches for $sa1 (regex for obfuscated var/new/return)
var _$ = "obfuscated_variable";

// String matches for structural JS components ($sa2, $sa6, $sa7)
function test_scanbox() {
    while (true) {
        return "analysis";
    }
}

// String matches for standard methods ($sa3, $sa4, $sa5, $sa8)
var a = (10).toString();
var b = "prism".toUpperCase();
var c = arguments.length;
var d = unescape("%41");

// String matches for Scanbox specific logic ($sa9 to $sa15)
var expire = 365*10*24*60*60*1000;
var bit1 = data >> 2;
var bit2 = (data & 3) << 4;
var bit3 = (data & 15) << 2;
var bit4 = (data >> 6) | 192;
var bit5 = (data & 63) | 128;
var bit6 = (data >> 12) | 224;