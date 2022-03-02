--WAF Action
require 'config';
local lib = require 'lib';
local ChainList = require 'ChainList';
local SWITCH_ON = "on";

--lib Init
lib.init(config_rule_dir, config_log_dir, config_waf_output, config_waf_redirect_url, config_output_html);

--allow white ip
local whiteIp = ChainList.newNode();
whiteIp.setEnable(SWITCH_ON == config_white_ip_check);
function whiteIp.run()
    if whiteIp.enable then
        local IP_WHITE_RULE = lib.get_rule('whiteip.rule');
        local WHITE_IP = lib.get_client_ip();
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if lib.ruleMatch(WHITE_IP,rule) then
                    --log_record('White_IP',ngx.var_request_uri,"_","_");
                    return true;
                end
            end
        end
    end
    return false;
end

--deny black ip
local blackIp = ChainList.newNode();
blackIp.setEnable(SWITCH_ON == config_black_ip_check);
function blackIp.run()
    if blackIp.enable then
        local IP_BLACK_RULE = lib.get_rule('blackip.rule');
        local BLACK_IP = lib.get_client_ip();
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if lib.ruleMatch(BLACK_IP,rule) then
                    lib.log_record('BlackList_IP',ngx.var_request_uri,"_","_");
                    ngx.exit(403);
                    return true;
                end
            end
        end
    end
    return false;
end

--allow white url
local whiteUrl = ChainList.newNode();
whiteUrl.setEnable(SWITCH_ON == config_white_url_check);
function whiteUrl.run()
    if whiteUrl.enable then
        local URL_WHITE_RULES = lib.get_rule('whiteurl.rule');
        local REQ_URI = ngx.var.request_uri;
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if lib.ruleMatch(REQ_URI,rule) then
                    return true;
                end
            end
        end
    end
    return false;
end

--deny cc attack
local ccAttack = ChainList.newNode();
ccAttack.setEnable(SWITCH_ON == config_cc_check);
local cc_rate = string.gmatch(config_cc_rate,'(%d+)/(%d+)');
local CCcount, CCseconds = cc_rate();
ccAttack.CCcount = tonumber(CCcount);
ccAttack.CCseconds = tonumber(CCseconds);
function ccAttack.run()
    if ccAttack.enable then
        local ATTACK_URI = ngx.var.uri;
        local CC_TOKEN = lib.get_client_ip()..ATTACK_URI;
        local limit = ngx.shared.limit;
        local req, _ = limit:get(CC_TOKEN);
        if req == nil then
            limit:set(CC_TOKEN, 1, ccAttack.CCseconds);
        elseif req > ccAttack.CCcount then
            lib.log_record('CC_Attack', ngx.var.request_uri, "-", "-");
            ngx.exit(403);
            return true;
        else
            limit:incr(CC_TOKEN,1);
        end
    end
    return false
end

--deny cookie
local cookieAttack = ChainList.newNode();
cookieAttack.setEnable(SWITCH_ON == config_cookie_check);
function cookieAttack.run()
    if cookieAttack.enable then
        local COOKIE_RULES = lib.get_rule('cookie.rule');
        local USER_COOKIE = ngx.var.http_cookie;
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if lib.ruleMatch(USER_COOKIE,rule) then
                    lib.log_record('Deny_Cookie',ngx.var.request_uri,"-",rule);
                    lib.waf_output();
                    return true;
                end
            end
        end
    end
    return false
end

--deny url
local urlAttack = ChainList.newNode();
urlAttack.setEnable(SWITCH_ON == config_url_check);
function urlAttack.run()
    if urlAttack.enable then
        local URL_RULES = lib.get_rule('url.rule');
        local REQ_URI = ngx.var.request_uri;
        for _,rule in pairs(URL_RULES) do
            if lib.ruleMatch(REQ_URI, rule) then
                lib.log_record('Deny_URL',REQ_URI,"-",rule);
                lib.waf_output();
                return true;
            end
        end
    end
    return false
end

--deny url args
local urlArgsAttack = ChainList.newNode();
urlArgsAttack.setEnable(SWITCH_ON == config_url_args_check);
function urlArgsAttack.run()
    if urlArgsAttack.enable then
        local ARGS_RULES = lib.get_rule('args.rule');
        local REQ_ARGS = ngx.req.get_uri_args();
        for _,rule in pairs(ARGS_RULES) do
            if lib.walkArge(REQ_ARGS, rule) then
                lib.log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule);
                lib.waf_output();
                return true;
            end
        end
    end
    return false
end

--deny user agent
local userAgentAttack = ChainList.newNode();
userAgentAttack.setEnable(SWITCH_ON == config_user_agent_check);
function userAgentAttack.run()
    if userAgentAttack.enable then
        local USER_AGENT_RULES = lib.get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if lib.ruleMatch(USER_AGENT,rule) then
                    lib.log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule);
                    lib.waf_output();
                    return true;
                end
            end
        end
    end
    return false;
end

--deny post
local postAttack = ChainList.newNode();
postAttack.setEnable(SWITCH_ON == config_post_check);
function postAttack.run()
    if postAttack.enable then
        local POST_RULES = lib.get_rule('post.rule');
        local POST_ARGS = ngx.req.get_post_args();
        for _,rule in pairs(POST_RULES) do
            if lib.walkArge(POST_ARGS, rule) then
                lib.log_record('Deny_Post_Args',key.."->"..val,"-",rule);
                lib.waf_output();
                return true;
            end
        end
    end
    return false;
end

ChainList.setEnable(SWITCH_ON == config_waf_enable);

ChainList.addNode(whiteIp);
ChainList.addNode(blackIp);
ChainList.addNode(userAgentAttack);
ChainList.addNode(ccAttack);
ChainList.addNode(cookieAttack);
ChainList.addNode(whiteUrl);
ChainList.addNode(urlAttack);
ChainList.addNode(urlArgsAttack);
ChainList.addNode(postAttack);

return ChainList;
