function main(arg_name_to_scan)
	pcall(require, "m")
	local ok, http = pcall(require, "socket.http")
	if not ok then
		m.log(2, "Antispam Plugin ERROR: LuaSocket library not installed, please install it or disable this plugin.")
		return nil
	end
	-- part of LuaSocket library
	local ok, ltn12 = pcall(require, "ltn12")
	local ok, json = pcall(require, "json")
	if not ok then
		m.log(2, "Antispam Plugin ERROR: LuaJSON library not installed, please install it or disable this plugin.")
		return nil
	end
	args = m.getvars("ARGS", "none")
	for key, arg in pairs(args) do
		if arg_name_to_scan == string.sub(arg["name"], 6) then
			-- Windows-style new line needs to be added at the beginning of the data to simulate empty SMTP headers as Rspamd is adjusted for e-mail traffic
			data_to_scan = string.format([[\r\n%s]], arg["value"])
			break
		end
	end
	local source = ltn12.source.string(data_to_scan)
	headers = {
		["Content-Length"] = string.len(data_to_scan);
		["Settings"] = "symbols_enabled = ['GTUBE', 'BAYES_SPAM', 'BAYES_HAM'];";
		["Hostname"] = "localhost"
	}
	local respbody = {}
	local client, code, headers, status = http.request {
		url=string.format("http://%s:%s/checkv2", m.getvar("tx.antispam-plugin_rspamd_address"), m.getvar("tx.antispam-plugin_rspamd_port")),
		method="POST",
		source=source,
		headers=headers,
		sink = ltn12.sink.table(respbody)
	}
	if client == nil then
		m.log(2, string.format("Antispam Plugin ERROR: Cannot connect to rspamd at %s:%s: %s.", m.getvar("tx.antispam-plugin_rspamd_address"), m.getvar("tx.antispam-plugin_rspamd_port"), code))
		return nil
	end
	respbody_json = json.decode(table.concat(respbody))
	local gtube = false
	local gtube_action = nil
	for key, value in pairs(respbody_json["symbols"]) do
		if key == "GTUBE" then
			gtube = true
			gtube_action = respbody_json["action"]
			break
		end
	end
	if gtube == true then
		m.setvar("tx.antispam-plugin_spam_score", 0)
		if gtube_action == "no action" then
			m.setvar("tx.antispam-plugin_spam_flag", "0")
		else
			m.setvar("tx.antispam-plugin_spam_flag", "1")
		end
	else
		m.setvar("tx.antispam-plugin_spam_score", respbody_json["score"])
		if tonumber(m.getvar("tx.antispam-plugin_use_rspamd_threshold")) == 1 then
			threshold = respbody_json["required_score"]
		else
			threshold = tonumber(m.getvar("tx.antispam-plugin_spam_threshold"))
		end
		if respbody_json["score"] >= threshold then
			m.setvar("tx.antispam-plugin_spam_flag", "1")
		else
			m.setvar("tx.antispam-plugin_spam_flag", "0")
		end
	end
	-- we need to return something for rule to trigger
	return ""
end
