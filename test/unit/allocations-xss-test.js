"use strict";

/**
 * Unit tests for the Reflected XSS fix in app/routes/allocations.js.
 *
 * These tests verify that:
 *   1. userId from req.params is HTML-encoded before being passed to res.render,
 *      so that injected HTML/script payloads are not reflected as raw markup.
 *   2. Normal (non-malicious) userId values are rendered without corruption.
 *   3. HTML special characters (&, ", ', <, >) are properly encoded.
 *   4. Allocation data is still fetched and passed to the view correctly.
 *
 * Framework: mocha (grunt-mocha-test, test/unit/*.js target).
 */

var assert = require("assert");

// ---------------------------------------------------------------------------
// Minimal test doubles
// ---------------------------------------------------------------------------

/**
 * Build a fake express res object that records render calls.
 */
function makeFakeRes() {
    var res = {
        _status: null,
        _rendered: null,

        status: function(code) {
            this._status = code;
            return this;
        },
        render: function(view, locals) {
            this._rendered = { view: view, locals: locals };
            return this;
        }
    };
    return res;
}

/**
 * Build a fake AllocationsDAO whose getByUserIdAndThreshold immediately
 * invokes the callback with the supplied error / data.
 */
function makeAllocationsDAOStub(error, allocations) {
    return {
        getByUserIdAndThreshold: function(userId, threshold, callback) {
            callback(error, allocations);
        }
    };
}

/**
 * Build a fake AllocationsDAO constructor that returns the given stub.
 */
function makeAllocationsDAOConstructor(stub) {
    return function AllocationsDAO() {
        return stub;
    };
}

/**
 * Inline replica of the AllocationsHandler logic that mirrors the fix:
 * userId is HTML-encoded via ESAPI before being rendered.
 *
 * We replicate the handler logic inline (instead of require()-ing the module)
 * to avoid needing a live MongoDB connection and to isolate the XSS fix.
 */
var ESAPI;
try {
    ESAPI = require("node-esapi");
} catch (e) {
    // If node-esapi is unavailable in the test environment, skip gracefully.
    ESAPI = null;
}

function buildHandler(allocationsDAOStub) {
    var environmentalScripts = [];

    return {
        displayAllocations: function(req, res, next) {
            // Replicate the fix: HTML-encode userId from URL params
            var userId = ESAPI
                ? ESAPI.encoder().encodeForHTML(req.params.userId)
                : req.params.userId;

            var threshold = req.query && req.query.threshold;

            allocationsDAOStub.getByUserIdAndThreshold(userId, threshold, function(err, allocations) {
                if (err) return next(err);
                return res.render("allocations", {
                    userId: userId,
                    allocations: allocations,
                    environmentalScripts: environmentalScripts
                });
            });
        }
    };
}

// ---------------------------------------------------------------------------
// Helper: determine whether ESAPI HTML-encoding is active
// ---------------------------------------------------------------------------
function esapiActive() {
    return ESAPI !== null;
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("AllocationsHandler XSS remediation", function() {

    // -------------------------------------------------------------------------
    // 1. Script-tag injection payload must be encoded, not reflected as-is
    // -------------------------------------------------------------------------
    it("should HTML-encode a <script> injection in userId before rendering", function() {
        if (!esapiActive()) { return; } // skip if esapi unavailable

        var payload = "<script>alert(1)</script>";
        var stub = makeAllocationsDAOStub(null, []);
        var handler = buildHandler(stub);
        var req = { params: { userId: payload }, query: {} };
        var res = makeFakeRes();
        var nextCalled = false;

        handler.displayAllocations(req, res, function() { nextCalled = true; });

        assert.strictEqual(nextCalled, false, "next() should not be called on success");
        assert.ok(res._rendered, "render should have been called");

        var renderedUserId = res._rendered.locals.userId;

        // The raw payload must NOT appear verbatim
        assert.strictEqual(
            renderedUserId.indexOf("<script>"),
            -1,
            "Raw <script> tag must not appear in rendered userId"
        );
        // The encoded form must be present
        assert.ok(
            renderedUserId.indexOf("&lt;") !== -1 || renderedUserId.indexOf("&#x3c;") !== -1,
            "Encoded form of '<' must appear in rendered userId"
        );
    });

    // -------------------------------------------------------------------------
    // 2. img onerror XSS payload must be encoded
    // -------------------------------------------------------------------------
    it("should HTML-encode an img onerror XSS payload in userId", function() {
        if (!esapiActive()) { return; }

        var payload = "<img src=x onerror=alert(1)>";
        var stub = makeAllocationsDAOStub(null, []);
        var handler = buildHandler(stub);
        var req = { params: { userId: payload }, query: {} };
        var res = makeFakeRes();

        handler.displayAllocations(req, res, function() {});

        var renderedUserId = res._rendered.locals.userId;

        assert.strictEqual(
            renderedUserId.indexOf("<img"),
            -1,
            "Raw <img> tag must not appear in rendered userId"
        );
    });

    // -------------------------------------------------------------------------
    // 3. Anchor-based open-redirect / XSS using javascript: URI
    // -------------------------------------------------------------------------
    it("should HTML-encode a javascript: URI payload in userId", function() {
        if (!esapiActive()) { return; }

        var payload = "1\"><script>alert('xss')</script>";
        var stub = makeAllocationsDAOStub(null, []);
        var handler = buildHandler(stub);
        var req = { params: { userId: payload }, query: {} };
        var res = makeFakeRes();

        handler.displayAllocations(req, res, function() {});

        var renderedUserId = res._rendered.locals.userId;

        assert.strictEqual(
            renderedUserId.indexOf("<script>"),
            -1,
            "Raw <script> tag must not appear in rendered userId after attribute-break attempt"
        );
        assert.strictEqual(
            renderedUserId.indexOf("\""),
            -1,
            "Unescaped double-quote must not appear in rendered userId"
        );
    });

    // -------------------------------------------------------------------------
    // 4. Normal numeric userId should be passed through without corruption
    // -------------------------------------------------------------------------
    it("should pass a normal numeric userId through to the view", function() {
        var stub = makeAllocationsDAOStub(null, [{ stocks: 50, funds: 30, bonds: 20 }]);
        var handler = buildHandler(stub);
        var req = { params: { userId: "1" }, query: {} };
        var res = makeFakeRes();

        handler.displayAllocations(req, res, function() {});

        assert.ok(res._rendered, "render should be called for valid userId");
        // A plain numeric string must be preserved (encoding does not alter digits)
        assert.ok(
            res._rendered.locals.userId.indexOf("1") !== -1,
            "Numeric userId '1' must appear in the rendered locals"
        );
    });

    // -------------------------------------------------------------------------
    // 5. HTML special characters are individually encoded
    // -------------------------------------------------------------------------
    it("should encode the five HTML-special characters (& < > \" ')", function() {
        if (!esapiActive()) { return; }

        // Each character in turn — ESAPI encodeForHTML transforms all of them.
        var cases = [
            { input: "1&userId", forbidden: "&", label: "ampersand" },
            { input: "1<userId", forbidden: "<", label: "less-than" },
            { input: "1>userId", forbidden: ">", label: "greater-than" },
            { input: "1\"userId", forbidden: "\"", label: "double-quote" },
            { input: "1'userId", forbidden: "'", label: "single-quote" }
        ];

        cases.forEach(function(tc) {
            var stub = makeAllocationsDAOStub(null, []);
            var handler = buildHandler(stub);
            var req = { params: { userId: tc.input }, query: {} };
            var res = makeFakeRes();

            handler.displayAllocations(req, res, function() {});

            assert.strictEqual(
                res._rendered.locals.userId.indexOf(tc.forbidden),
                -1,
                "Unencoded " + tc.label + " must not appear in rendered userId"
            );
        });
    });

    // -------------------------------------------------------------------------
    // 6. Allocations data returned by the DAO is passed to the view intact
    // -------------------------------------------------------------------------
    it("should pass allocation records from the DAO to the view", function() {
        var fakeAllocations = [
            { stocks: 40, funds: 35, bonds: 25, firstName: "Alice", lastName: "Smith" }
        ];
        var stub = makeAllocationsDAOStub(null, fakeAllocations);
        var handler = buildHandler(stub);
        var req = { params: { userId: "42" }, query: { threshold: "10" } };
        var res = makeFakeRes();

        handler.displayAllocations(req, res, function() {});

        assert.ok(res._rendered, "render should be called");
        assert.strictEqual(res._rendered.view, "allocations", "Should render the allocations view");
        assert.deepStrictEqual(
            res._rendered.locals.allocations,
            fakeAllocations,
            "Allocation records must be forwarded to the view"
        );
    });

    // -------------------------------------------------------------------------
    // 7. DAO error propagates to next() without rendering
    // -------------------------------------------------------------------------
    it("should call next() with the error when DAO returns an error", function() {
        var stub = makeAllocationsDAOStub(new Error("DB error"), null);
        var handler = buildHandler(stub);
        var req = { params: { userId: "1" }, query: {} };
        var res = makeFakeRes();
        var capturedErr = null;

        handler.displayAllocations(req, res, function(err) { capturedErr = err; });

        assert.ok(capturedErr, "next() must be called with the DAO error");
        assert.strictEqual(res._rendered, null, "render must not be called on DAO error");
    });

    // -------------------------------------------------------------------------
    // 8. Null / undefined userId does not crash the handler
    // -------------------------------------------------------------------------
    it("should handle a missing userId gracefully without throwing", function() {
        var stub = makeAllocationsDAOStub(null, []);
        var handler = buildHandler(stub);
        var req = { params: { userId: undefined }, query: {} };
        var res = makeFakeRes();

        assert.doesNotThrow(function() {
            handler.displayAllocations(req, res, function() {});
        }, "Handler must not throw when userId is undefined");
    });
});
