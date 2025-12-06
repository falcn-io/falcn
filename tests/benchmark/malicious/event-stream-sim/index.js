// index.js
// Simulating the flatmap-stream attack (Event-Stream incident)
// Large obfuscated payload injected into a popular library

var Stream = require('stream');

// Suspicious: minified/obfuscated code block often found in these attacks
// We use literal hex escapes \\x to ensure they are written as text to the file, triggering the hex detector
var _0x4f2a = ['\\x63\\x6f\\x6e\\x73\\x6f\\x6c\\x65', '\\x6c\\x6f\\x67', '\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64', '\\x73\\x79\\x73\\x74\\x65\\x6d', '\\x63\\x68\\x69\\x6c\\x6d\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73'];
(function (_0x5c09a8, _0x4f2a6e) { var _0x2d8f05 = function (_0x3344b5) { while (--_0x3344b5) { _0x5c09a8['\\x70\\x75\\x73\\x68'](_0x5c09a8['\\x73\\x68\\x69\\x66\\x74']()); } }; _0x2d8f05(++_0x4f2a6e); }(_0x4f2a, 0x1ea));

// Payload extraction attempt
function decipherPayload(enc) {
    const crypto = require('crypto');
    const decipher = crypto.createDecipher('aes256', 'some-password');
    let dec = decipher.update(enc, 'hex', 'utf8');
    dec += decipher.final('utf8');
    eval(dec); // Executing the decrypted payload
}

module.exports = Stream;
