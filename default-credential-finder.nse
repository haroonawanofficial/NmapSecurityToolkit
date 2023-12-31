description = [[
This NSE script scans for potential default password usage in login forms of routers, switches, IoT devices, and other web interfaces.
]]

---
-- @usage nmap -p80,443 --script http-default-passwords.nse <target>
--
-- This script detects potential default password usage in web login forms.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-default-passwords:
-- |   Potential Default Password Found:
-- |     Website: http://device.example.com:80
-- |     Port: 80
-- |     Form Action: /login
-- |     Default Username: admin
-- |     Default Password: admin
-- |_  Request: GET /login
--

categories = {"auth", "vuln"}
author = "Haroon Ahmad Awan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local httpspider = require "httpspider"

-- Patterns to detect login forms
local LOGIN_FORM_PATTERNS = {
    '<form[^>]*action="([^"]+)".-</form>', -- Capturing the content within form tags and the action attribute
}

-- Default username and password combinations to check
local DEFAULT_PASSWORDS = {
    {username = "admin", password = "admin"},
    {username = "root", password = "root"},
    -- Add more default combinations here
}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
    local singlepages = stdnse.get_script_args("http-default-passwords.singlepages")
    local defaultPasswordVulns = {}
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
            for _, pattern in ipairs(LOGIN_FORM_PATTERNS) do
                for match in string.gmatch(response.body, pattern) do
                    local formAction = match
                    local request = "GET " .. formAction

                    for _, defaultPass in pairs(DEFAULT_PASSWORDS) do
                        table.insert(defaultPasswordVulns, {
                            "Website: " .. host.ip .. ":" .. port.number,
                            "Port: " .. port.number,
                            "Form Action: " .. formAction,
                            "Default Username: " .. defaultPass.username,
                            "Default Password: " .. defaultPass.password,
                            "Request: " .. request,
                            "Response: N/A",
                        })
                    end
                end
            end
            if index then
                index = index + 1
            else
                index = 1
            end
        end
    end

    if #defaultPasswordVulns == 0 then
        return "No potential default passwords found."
    end

    table.insert(defaultPasswordVulns, 1, "Potential Default Password Found:")
    defaultPasswordVulns.name = crawler:getLimitations()

    return stdnse.format_output(true, defaultPasswordVulns)
end
