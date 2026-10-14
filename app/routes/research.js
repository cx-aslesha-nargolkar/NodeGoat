const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

// Allowlist of permitted hostnames for outbound research requests.
// Only requests to these hosts will be forwarded by the server.
const ALLOWED_RESEARCH_HOSTS = [
    "finance.yahoo.com"
];

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            // Validate the base URL using the stdlib URL parser and an explicit
            // host allowlist to prevent SSRF (CWE-918). User-supplied values
            // from req.query.url and req.query.symbol must not be used to
            // construct an arbitrary outbound request.
            let parsedUrl;
            try {
                parsedUrl = new URL(req.query.url);
            } catch (e) {
                return res.status(400).send("Invalid URL");
            }

            if (!ALLOWED_RESEARCH_HOSTS.includes(parsedUrl.hostname)) {
                return res.status(400).send("URL host is not permitted");
            }

            // Build the request URL from the validated base and the symbol.
            const url = req.query.url + req.query.symbol;
            return needle.get(url, (error, newResponse, body) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;
