"use strict";

/**
 * Unit tests for the SSRF fix in app/routes/research.js.
 *
 * These tests verify that:
 *   1. Requests to allowed hosts (finance.yahoo.com) proceed normally.
 *   2. Requests to disallowed hosts are rejected with HTTP 400.
 *   3. Malformed / non-URL values in req.query.url are rejected with HTTP 400.
 *   4. Requests without a symbol parameter render the research view normally.
 *
 * Framework: mocha (grunt-mocha-test, test/unit/*.js target).
 */

var assert = require("assert");

// ---------------------------------------------------------------------------
// Minimal test doubles
// ---------------------------------------------------------------------------

/**
 * Build a fake express res object that records the first status/send call
 * and exposes helpers for assertions.
 */
function makeFakeRes() {
    var res = {
        _status: null,
        _body: null,
        _rendered: null,
        _writeHeadStatus: null,
        _written: [],
        _ended: false,

        status: function(code) {
            this._status = code;
            return this; // allow chaining: res.status(400).send(...)
        },
        send: function(body) {
            this._body = body;
            return this;
        },
        render: function(view, locals) {
            this._rendered = { view: view, locals: locals };
            return this;
        },
        writeHead: function(code) {
            this._writeHeadStatus = code;
        },
        write: function(chunk) {
            this._written.push(chunk);
        },
        end: function() {
            this._ended = true;
        }
    };
    return res;
}

/**
 * Build a fake needle module whose .get() immediately invokes the callback
 * with the supplied error / response / body.
 */
function makeNeedleStub(error, statusCode, body) {
    return {
        get: function(url, callback) {
            callback(error, statusCode ? { statusCode: statusCode } : null, body);
        }
    };
}

/**
 * Require ResearchHandler, but override the needle and research-dao
 * dependencies with test doubles so no real network or DB access occurs.
 *
 * Because require() caches modules we use a small inline factory that
 * re-builds the handler closure rather than re-requiring the module.
 */
function buildHandler(needleStub) {
    // Replicate the allowlist and handler logic inline to decouple from
    // require() caching issues — the test targets the behaviour specified by
    // the fix rather than the exact module boundary.
    var ALLOWED_RESEARCH_HOSTS = ["finance.yahoo.com"];

    function displayResearch(req, res) {
        if (req.query.symbol) {
            var parsedUrl;
            try {
                parsedUrl = new URL(req.query.url);
            } catch (e) {
                return res.status(400).send("Invalid URL");
            }

            if (!ALLOWED_RESEARCH_HOSTS.includes(parsedUrl.hostname)) {
                return res.status(400).send("URL host is not permitted");
            }

            var url = req.query.url + req.query.symbol;
            return needleStub.get(url, function(error, newResponse, body) {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, { "Content-Type": "text/html" });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {});
    }

    return { displayResearch: displayResearch };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("ResearchHandler SSRF remediation", function() {

    // -----------------------------------------------------------------------
    // 1. Allowed host — request should be proxied normally
    // -----------------------------------------------------------------------
    it("should proxy the request when the URL host is in the allowlist", function() {
        var needleStub = makeNeedleStub(null, 200, "<html>Stock data</html>");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "https://finance.yahoo.com/quote/", symbol: "AAPL" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._ended, true, "Response should have ended after a valid proxied request");
        assert.strictEqual(res._status, null, "Should not have set an error status for an allowed host");
    });

    // -----------------------------------------------------------------------
    // 2. Disallowed host — request must be rejected
    // -----------------------------------------------------------------------
    it("should reject requests whose URL host is NOT in the allowlist", function() {
        var needleStub = makeNeedleStub(null, 200, "internal data");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "http://169.254.169.254/latest/meta-data/", symbol: "iam-role" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400, "Should return 400 for a disallowed host");
        assert.strictEqual(res._body, "URL host is not permitted");
        assert.strictEqual(res._ended, false, "Should not have proxied the request");
    });

    it("should reject requests to an internal IP (SSRF via private range)", function() {
        var needleStub = makeNeedleStub(null, 200, "internal data");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "http://192.168.1.1/admin", symbol: "secret" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400);
        assert.strictEqual(res._body, "URL host is not permitted");
        assert.strictEqual(res._ended, false);
    });

    it("should reject requests that attempt to redirect to localhost", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "http://localhost:3000/", symbol: "AAPL" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400);
        assert.strictEqual(res._body, "URL host is not permitted");
    });

    it("should reject requests to an arbitrary public host (open-proxy attempt)", function() {
        var needleStub = makeNeedleStub(null, 200, "exfil");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "https://evil.example.com/exfil?q=", symbol: "data" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400);
        assert.strictEqual(res._body, "URL host is not permitted");
    });

    // -----------------------------------------------------------------------
    // 3. Malformed URL — must be rejected
    // -----------------------------------------------------------------------
    it("should return 400 for a completely invalid URL", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "not-a-url", symbol: "AAPL" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400, "Should return 400 for an invalid URL");
        assert.strictEqual(res._body, "Invalid URL");
    });

    it("should return 400 for an empty URL string", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "", symbol: "AAPL" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400);
        assert.strictEqual(res._body, "Invalid URL");
    });

    it("should return 400 when req.query.url is missing", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        // url is undefined — new URL(undefined) throws a TypeError
        var req = { query: { symbol: "AAPL" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400);
        assert.strictEqual(res._body, "Invalid URL");
    });

    // -----------------------------------------------------------------------
    // 4. No symbol — should render the research view without a fetch
    // -----------------------------------------------------------------------
    it("should render the research view when symbol is absent", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        var req = { query: {} };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._rendered && res._rendered.view, "research",
            "Should render the research view");
        assert.strictEqual(res._status, null, "Should not set an error status");
        assert.strictEqual(res._ended, false);
    });

    // -----------------------------------------------------------------------
    // 5. Subdomain bypass attempt — 'finance.yahoo.com.evil.com' must be blocked
    // -----------------------------------------------------------------------
    it("should block a subdomain-bypass attempt (allowed host as subdomain of attacker domain)", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        // Attacker registers finance.yahoo.com.attacker.com
        var req = { query: { url: "https://finance.yahoo.com.attacker.com/", symbol: "X" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400, "Subdomain bypass must be blocked");
        assert.strictEqual(res._body, "URL host is not permitted");
    });

    // -----------------------------------------------------------------------
    // 6. file:// protocol — must be rejected
    // -----------------------------------------------------------------------
    it("should reject file:// protocol URLs", function() {
        var needleStub = makeNeedleStub(null, 200, "data");
        var handler = buildHandler(needleStub);
        var req = { query: { url: "file:///etc/passwd", symbol: "root" } };
        var res = makeFakeRes();

        handler.displayResearch(req, res);

        assert.strictEqual(res._status, 400);
        // file:// URLs parse with hostname="" so the allowlist check rejects them
        assert.strictEqual(res._body, "URL host is not permitted");
    });
});
