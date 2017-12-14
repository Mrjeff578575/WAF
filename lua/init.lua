local waf_path = "/user/local/WAF/"
local ngxmatch = ngx.re.match
function getClientIp()
        IP = ngx.var.remote_addr
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

function readfile(path)
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
local ipWhitelist = readfile(waf_path.."config/blocklist")
local ipBlocklist = readfile(waf_path.."config/whitelist")

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
