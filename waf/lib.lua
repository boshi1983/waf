--waf core lib
local lib = {
    rule_dir = "",
    log_dir = "",
    output = "",
    redirect_url = "",
    output_html = "",
};

--lib construction
function lib.init(rule_dir, log_dir, waf_output, waf_redirect_url, output_html)
    lib.rule_dir = rule_dir;
    lib.log_dir = log_dir;
    lib.output = waf_output;
    lib.redirect_url = waf_redirect_url;
    lib.output_html = output_html;
end

--Get the client IP
function lib.get_client_ip()
    local header = ngx.req.get_headers();
    local CLIENT_IP = header["X_real_ip"];
    if CLIENT_IP == nil then
        CLIENT_IP = header["X_Forwarded_For"];
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr;
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown";
    end
    return CLIENT_IP;
end

--Get the client user agent
function lib.get_user_agent()
    local USER_AGENT = ngx.var.http_user_agent;
    if USER_AGENT == nil then
       USER_AGENT = "unknown";
    end
    return USER_AGENT;
end

--Get WAF rule
function lib.get_rule(rulefilename)
    local io = require 'io';
    local RULE_PATH = lib.rule_dir;
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r");
    local RULE_TABLE = {};
    if RULE_FILE ~= nil then
        for line in RULE_FILE:lines() do
            table.insert(RULE_TABLE, line);
        end
        RULE_FILE:close();
    end
    return(RULE_TABLE);
end

--WAF log record for json,(use logstash codec => json)
function lib.log_record(method,url,data,ruletag)
    local cjson = require("cjson");
    local io = require 'io';
    local LOG_PATH = lib.log_dir;
    local CLIENT_IP = lib.get_client_ip();
    local USER_AGENT = lib.get_user_agent();
    local SERVER_NAME = ngx.var.server_name;
    local LOCAL_TIME = ngx.localtime();
    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              };
    local LOG_LINE = cjson.encode(log_json_obj);
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log";
    local file = io.open(LOG_NAME,"a");
    if file == nil then
        return;
    end
    file:write(LOG_LINE.."\n");
    file:flush();
    file:close();
end

--WAF Match
function lib.ruleMatch(subject, rule)
    if rule == nil or rule == "" then
        return false;
    end
    local from, to, error = ngx.re.find(subject,rule,"jo");
    if from == nil and to == nil then
        return false;
    end
    return true;
end

--WAF return
function lib.waf_output()
    if lib.output == "redirect" then
        ngx.redirect(lib.redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(lib.output_html)
        ngx.exit(ngx.status)
    end
end

return lib;