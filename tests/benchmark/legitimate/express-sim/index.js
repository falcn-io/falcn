// index.js
// Networking code that IS legitimate (should not flag as suspicious network activity)

const http = require('http');

function createServer() {
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello World\n');
    });
    return server;
}

module.exports = createServer;
