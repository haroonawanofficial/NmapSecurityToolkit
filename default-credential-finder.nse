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
 '<form[^>]*>', -- Look for form tags
    '<input[^>]*name=["\']*(%w+)["\']*%s*[^>]*>', -- Look for input fields with names
  '<form[^>]*action="([^"]+)".-</form>', -- Capturing the content within form tags and the action attribute
    '<form[^>]*action="([^"]+)".-</form>', -- Another pattern to capture form action (add more patterns as needed)
    '<input[^>]*type="hidden"[^>]*name="([^"]+)".-</form>', -- Pattern to capture hidden input fields that might be related to authentication
   
}

-- Default username and password combinations to check
local DEFAULT_PASSWORDS = {
    {username = "admin", password = "12345"},
    {username = "Admin", password = "123456"},
    {username = "admin", password = "admin"},
    {username = "admin", password = "9999"},
    {username = "admin", password = "1234"},
    {username = "Administrator", password = ""},
    {username = "root", password = "pass"},
    {username = "root", password = ""},
    {username = "service", password = "service"},
    {username = "Dinion", password = ""},
    {username = "root", password = "camera"},
    {username = "", password = "no default"},
    {username = "888888", password = "888888"},
    {username = "666666", password = "666666"},
    {username = "admin", password = "fliradmin"},
    {username = "Admin", password = "1234"},
    {username = "root", password = "admin"},
    {username = "administrator", password = "1234"},
    {username = "admin", password = "1111"},
    {username = "admin", password = "Model # of Camera"},
    {username = "admin", password = "meinsm"},
    {username = "root", password = "root"},
    {username = "root", password = "4321"},
    {username = "admin", password = "4321"},
    {username = "admin", password = "1111111"},
    {username = "telecomadmin", password = "admintelecom"},
    {username = "admin", password = "jvc"},
    {username = "admin", password = "no default password"},
    {username = "admin", password = "password"},
    {username = "admin", password = "ubnt"},
    {username = "supervisor", password = "supervisor"}
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
