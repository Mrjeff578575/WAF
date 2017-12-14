local waf_path = "/home/jeff/Downloads/work/conf/WAF/"
local log_path = "/home/jeff/Downloads/work/conf/WAF/log/"
local ngxmatch = ngx.re.match
function getClientIp()
        IP = ngx.var.remote_addr
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(str)
    local filename = log_path.."test.log"
    write(filename, str.."\n")
end

function readfile(path)
    log(path)
    local fd = io.open(path, 'r')
    if fd == nil then
        return
    end
    local lines = {}
    for line in fd:lines() do
        table.insert(lines, line)
    end
    fd:close()
    return lines
end

local forbidden_html = readfile(waf_path.."config/Forbidden.html")
local ipBlocklist= readfile(waf_path.."config/blocklist")
local ipWhitelist = readfile(waf_path.."config/whitelist")

function whiteurl()
    if wturlrules ~= nil then
        for _,rule in pairs(wturlrules) do
            if ngxmatch(ngx.var.uri, rule, "isjo") then
                return true
            end
        end
    end
    return false
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
    return false
end

function blockip()
    if next(ipBlocklist) ~= nil then
        for _,ip in pairs(ipBlocklist) do
            if getClientIp()==ip then
                ngx.say(forbidden_html)
                ngx.exit(403)
            return true
            end
        end
    end
    return false
end
