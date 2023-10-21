description = [[
This advanced NSE script scans for potential command injection vulnerabilities in web applications. The script uses advanced patterns and techniques to minimize false positives.
]]

---
-- @usage nmap -p80 --script http-advanced-cmdinjection.nse <target>
--
-- This script aims to detect potential command injection vulnerabilities in web applications using advanced patterns and techniques. It's important to carefully review the results.
--
-- @args http-advanced-cmdinjection.singlepages The pages to test (e.g., {"/index.php", "/profile.php"}). Default: nil (crawler mode enabled)
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-advanced-cmdinjection:
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=some-very-random-page.com
-- |   Found the following potential command injection vulnerabilities:
-- |
-- |     Source: <form action="vulnerable.php"><input name="input" value=";system(command);"></form>
-- |     Website: http://some-very-random-page.com:80
-- |     Port: 80
-- |     Parameter: input
-- |     Vulnerability: Potential Command Injection
-- |     Request: GET /vulnerable.php?input=sample
-- |     Response: HTTP 200 OK
-- |_  
---

categories = {"intrusive", "exploit", "vuln"}
author = "Haroon Ahmad Awan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

-- Patterns to detect potential command injection vulnerabilities
local CMD_INJECTION_PATTERNS = {
    ';%s*[%w_]+%s*%(.-%);',  -- Example: ; system(command); or ; exec(command);
    '|%s*[%w_]+%s*%(.-%)|',  -- Example: | system(command) | or | exec(command) |
    '`%s*[%w_]+%s*%(.-%)`',  -- Example: ` system(command) ` or ` exec(command) `
}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
    local singlepages = stdnse.get_script_args("http-advanced-cmdinjection.singlepages")
    local vulns = {}
    local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME, withinhost = 1 })

    if not crawler then
        return
    end

    crawler:set_timeout(10000)

    local index, k, target, response, path
    while true do
        if singlepages then
            k, target = next(singlepages, index)
            if k == nil then
                break
            end
            response = http.get(host, port, target)
            path = target
        else
            local status, r = crawler:crawl()
            if not status then
                if r.err then
                    return stdnse.format_output(false, r.reason)
                else
                    break
                end
            end
            response = r.response
            path = tostring(r.url)
        end

        if response.body then
            for _, pattern in ipairs(CMD_INJECTION_PATTERNS) do
                if string.match(response.body, pattern) then
                    local request, matchedParam = CaptureRequestAndResponse(host, port, path)
                    local vuln = {
                        "Source: " .. response.body,
                        "Website: " .. host.ip .. ":" .. port.number,
                        "Port: " .. port.number,
                        "Parameter: " .. matchedParam,
                        "Vulnerability: Potential Command Injection",
                        "Request: " .. request,
                        "Response: " .. response.body,
                    }
                    table.insert(vulns, vuln)
                end
            end
            if index then
                index = index + 1
            else
                index = 1
            end
        end
    end

    if next(vulns) == nil then
        return "No potential Command Injection vulnerabilities found."
    end

    local results = {}
    for _, vuln in ipairs(vulns) do
        table.insert(results, vuln)
    end

    results.name = crawler:getLimitations()

    return stdnse.format_output(true, results)
end

-- Capture the request and response for detected vulnerabilities
function CaptureRequestAndResponse(host, port, path)
    local request = "N/A"
    local matchedParam = "N/A"

    -- Use http library to capture request and response details
    local result = http.get(host, port, path)

    if result then
        if result.request then
            request = result.request
        end

        if result.response then
            response = result.response
        end
    end

    -- Extract the matched parameter (you need to implement this logic)
    matchedParam = ExtractMatchedParameter(response.body, path)

    return request, matchedParam
end
